"""Opt-in LN access purchases, shared by the four Task transports.

W2/W3/W6 at Charter 563300b0. Private operations (including proofs) live only
in memory. Exceptions and snapshots never contain a challenge, proof or body.
The authenticated Edge owns payment finality, grants and the Origin fence.
"""
from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re
import threading
import time
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from .task_contract import jcs_canonical_bytes
from .crypto.evm import derive_eip3009_requirement_nonce, validate_eip3009_payload, EIP3009_TYPES

ORIGIN = 'https://kari.mayim-mayim.com'
PURPOSE = 'lnchurch.access-quota'
SCHEMA = 'ln_church.access_quota.v1'
EXTENSION = 'lnchurch-access-quota'
ASSETS = {'eip155:8453': '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
          'eip155:84532': '0x036cbd53842c5426634e7929541ec2318f3dcf7e'}
_SAFE_CODES = {'ACCESS_REQUIRED', 'ACCESS_BUDGET_EXCEEDED', 'ACCESS_PENDING',
               'ACCESS_UNAVAILABLE', 'ACCESS_FAILED_FINAL', 'ACCESS_CONFLICT',
               'ACCESS_RESULT_EXPIRED', 'ACCESS_RESULT_UNAVAILABLE',
               'ACCESS_INVALID', 'ACCESS_SIGNING_FAILED'}


@dataclass(frozen=True)
class AccessQuotaTerms:
    purchase_id: str
    network: str
    asset: str
    pay_to: str
    amount_atomic: int
    purchased_requests: int
    reset_at: str


class AccessQuotaError(Exception):
    """Call the *same* client operation with the same shared policy to resume.

    origin_not_sent describes an authentic Edge challenge before dispatch,
    or its confirmed FAILED_FINAL purchase (which cannot dispatch Origin).
    It never declares a pending/PAID purchase or transport loss unsent.
    """
    def __init__(self, code: str, *, terms: Optional[AccessQuotaTerms] = None,
                 operation_id: Optional[str] = None, origin_not_sent: bool = False,
                 retry_after_seconds: Optional[float] = None) -> None:
        self.code = code if code in _SAFE_CODES else 'ACCESS_INVALID'
        self.terms = terms
        self.operation_id = operation_id
        self.origin_not_sent = origin_not_sent
        self.retry_after_seconds = retry_after_seconds
        super().__init__(self.code)

    def detached(self) -> 'AccessQuotaError':
        return AccessQuotaError(self.code, terms=self.terms, operation_id=self.operation_id,
                                origin_not_sent=self.origin_not_sent,
                                retry_after_seconds=self.retry_after_seconds)


def eligible(method: str, url: str) -> bool:
    p = urlsplit(url)
    if p.scheme != 'https' or p.netloc != 'kari.mayim-mayim.com' or p.fragment:
        return False
    return bool((method == 'GET' and re.fullmatch(r'/api/agent/tasks(?:/[^/]+)?', p.path))
                or (method == 'POST' and re.fullmatch(r'/api/agent/tasks/[^/]+/claim', p.path)))


def _headers(headers: Mapping[str, str]) -> dict:
    result = {}
    for key, value in headers.items():
        name = key.lower()
        if name in result or not isinstance(value, str):
            raise ValueError
        result[name] = value
    if sum(len(k) + len(v) + 4 for k, v in result.items()) > 32768:
        raise ValueError
    return result


def _json(raw: bytes, maximum: int = 131072) -> dict:
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise ValueError
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError
            d[k] = v
        return d
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if not isinstance(value, dict):
        raise ValueError
    return value


def _b64(value: str) -> dict:
    if not isinstance(value, str) or len(value) > 32768:
        raise ValueError
    return _json(base64.b64decode(value, validate=True))


def request_digest(method: str, url: str, headers: Mapping[str, str], body: bytes) -> str:
    h = _headers(headers)
    if method == 'GET' and body:
        raise ValueError
    value = dict(version=1, method=method, url=url, content_type=h.get('content-type'),
                 body_sha256=None if method == 'GET' else hashlib.sha256(body).hexdigest(),
                 idempotency_key=h.get('idempotency-key'))
    return hashlib.sha256(jcs_canonical_bytes(value)).hexdigest()


@dataclass(repr=False)
class _Operation:
    digest: str
    required: dict
    challenge: str
    payload: dict
    terms: AccessQuotaTerms
    proof: Optional[str] = None
    state: str = 'CHALLENGED'
    result_error: Optional[str] = None
    lock: Any = field(default_factory=threading.RLock)

    def __repr__(self):
        return '_AccessOperation(<private>)'


def _challenge(status, headers, body, method, url, request_headers, request_body, network):
    if status != 402 or not eligible(method, url):
        return None
    try:
        wire = _json(body)
    except Exception:
        return None
    ext = wire.get('extensions', {}).get(EXTENSION) if isinstance(wire.get('extensions', {}), dict) else None
    if not isinstance(ext, dict) or not isinstance(ext.get('info'), dict) or ext['info'].get('purpose') != PURPOSE:
        return None  # Origin / seller 402 is not an access challenge.
    try:
        h = _headers(headers)
        if h.get('content-encoding', 'identity').lower() != 'identity':
            raise ValueError
        if _b64(h['payment-required']) != wire or wire['x402Version'] != 2 or wire['error'] != 'payment_required':
            raise ValueError
        if wire['resource']['url'] != url or not isinstance(ext['schema'], dict):
            raise ValueError
        info = ext['info']
        if info['originDispatch'] != 'not_sent' or info['purchasedCreditsExpire'] is not False:
            raise ValueError
        if info['price'] != '0.01' or info['currency'] != 'USDC' or info['windowSeconds'] != 3600:
            raise ValueError
        if type(info['freeLimit']) is not int or info['freeLimit'] <= 0:
            raise ValueError
        reset = datetime.fromisoformat(info['resetAt'].replace('Z', '+00:00'))
        if reset.tzinfo is None:
            raise ValueError
        pid = info['purchaseId']
        if not isinstance(pid, str) or not re.fullmatch(r'aq_[a-f0-9]{32}', pid):
            raise ValueError
        identifier = wire['extensions']['payment-identifier']
        if identifier['info']['id'] != pid or not isinstance(identifier['schema'], dict):
            raise ValueError
        challenge = info['challenge']
        encoded, mac = challenge.split('.')
        if len(challenge) > 16384 or not re.fullmatch('[a-f0-9]{64}', mac):
            raise ValueError
        p = _b64(encoded)  # MAC verification belongs to AWS, never the client.
        digest = request_digest(method, url, request_headers, request_body)
        if p['version'] != 1 or p['purchase_id'] != pid or p['request_digest'] != digest:
            raise ValueError
        if (type(p['issued_at']) is not int or type(p['expires_at']) is not int
                or p['expires_at'] != p['issued_at'] + 300 or not isinstance(p['subject'], str)
                or not p['subject'] or p['policy_version'] != p['terms']['policy_version']):
            raise ValueError
        reqs = wire['accepts']
        if not isinstance(reqs, list) or len(reqs) != 1:
            raise ValueError
        req = reqs[0]
        terms = dict(p['terms'])
        count = terms.pop('purchased_requests'); terms.pop('policy_version')
        if terms != req or type(count) is not int or count <= 0 or count != info['purchasedRequests']:
            raise ValueError
        if (req['scheme'] != 'exact' or req['network'] != network or network not in ASSETS
                or req['asset'].lower() != ASSETS[network] or req['amount'] != '10000'
                or type(req['maxTimeoutSeconds']) is not int or req['maxTimeoutSeconds'] != 300
                or not re.fullmatch('0x[0-9a-fA-F]{40}', req['payTo']) or int(req['payTo'], 16) == 0
                or req['extra'] != dict(name='USD Coin', version='2', assetTransferMethod='eip3009', paymentFlow='upfront')):
            raise ValueError
        public = AccessQuotaTerms(pid, network, req['asset'], req['payTo'], 10000, count, info['resetAt'])
        return _Operation(digest, copy.deepcopy(wire), challenge, p, public)
    except Exception:
        pass
    raise AccessQuotaError('ACCESS_INVALID')


class AccessQuotaPolicy:
    """Share one instance across Task clients to share a locked access budget.

    budget_atomic is native-USDC atomic units, separate from PaymentPolicy.
    Explicit re-entry gets the caller's ordinary finite attempt budget; there
    is no automatic polling or sleeping. Keep this object while pending.
    """
    def __init__(self, *, allow: bool = False, budget_atomic: int = 0,
                 signer: Any = None, network: str = 'eip155:8453', wall_time=time.time):
        if type(allow) is not bool or type(budget_atomic) is not int or budget_atomic < 0 or network not in ASSETS:
            raise ValueError('Invalid access policy.')
        self.allow, self.budget_atomic, self.signer = allow, budget_atomic, signer
        self.network, self._wall_time = network, wall_time
        self._lock = threading.RLock()
        self._operations = {}
        self._purchases = {}
        self._reserved = {}
        self._spent = {}
        self._snapshots = {}
        self._readonly_purchase = ContextVar("ln_access_readonly", default=None)

    def __repr__(self):
        return 'AccessQuotaPolicy(<explicit access budget>)'

    @property
    def reserved_atomic(self):
        with self._lock:
            return sum(self._reserved.values())

    @property
    def spent_atomic(self):
        with self._lock:
            return sum(self._spent.values())

    @contextmanager
    def read_only(self, purchase_id):
        """Use the same client call to read this purchase, never create/settle it.

        Context-local: concurrent unrelated calls do not inherit the mode.
        """
        with self._lock:
            if purchase_id not in self._purchases:
                raise AccessQuotaError('ACCESS_CONFLICT')
        token = self._readonly_purchase.set(purchase_id)
        try:
            yield
        finally:
            self._readonly_purchase.reset(token)

    def has_operation(self, method, url, headers, body):
        """Whether same-request access continuation exists in this session."""
        key = request_digest(method, url, headers, body)
        with self._lock:
            return key in self._operations

    def snapshot(self, purchase_id):
        with self._lock:
            return copy.deepcopy(self._snapshots.get(purchase_id))

    def _error(self, code, op=None, retry=None):
        return AccessQuotaError(code, terms=op.terms if op else None,
            operation_id=op.terms.purchase_id if op else None,
            origin_not_sent=bool(op and op.state in {'CHALLENGED', 'FAILED_FINAL'}),
            retry_after_seconds=retry)

    def _reserve_and_sign(self, op, deadline, clock):
        if op.proof is not None:
            return
        if not self.allow or self.signer is None:
            raise self._error('ACCESS_REQUIRED', op)
        if clock() >= deadline:
            raise self._error('ACCESS_PENDING', op)
        pid = op.terms.purchase_id
        with self._lock:
            if pid not in self._reserved and pid not in self._spent:
                if sum(self._reserved.values()) + sum(self._spent.values()) + 10000 > self.budget_atomic:
                    raise self._error('ACCESS_BUDGET_EXCEEDED', op)
                self._reserved[pid] = 10000
        # Reserve before signing; only a server FAILED_FINAL releases a reservation.
        # A failed signer is not silently invoked again (it may already have signed).
        op.state = 'SIGNING'
        try:
            req = op.required['accepts'][0]
            now = int(self._wall_time())
            expiry = op.payload['expires_at']
            if now >= expiry or clock() >= deadline:
                raise ValueError
            requirement_hash = 'sha256:' + hashlib.sha256(jcs_canonical_bytes(op.payload)).hexdigest()
            nonce = derive_eip3009_requirement_nonce(requirement_hash, pid)
            if self.network == 'eip155:84532':
                # The generic SDK trust table intentionally remains unchanged.
                # This explicit testnet lane uses only the Architecture's native
                # Sepolia USDC domain and an already supplied signing account.
                from eth_account import Account
                from eth_account.messages import encode_typed_data
                account = getattr(self.signer, 'account', self.signer)
                auth = dict(from_=account.address, to=req['payTo'], value=req['amount'],
                            validAfter='0', validBefore=str(expiry), nonce=nonce)
                auth['from'] = auth.pop('from_')
                message = dict(auth)
                for key in ('value', 'validAfter', 'validBefore'):
                    message[key] = int(message[key])
                typed = encode_typed_data(domain_data=dict(name='USD Coin', version='2',
                    chainId=84532, verifyingContract=req['asset']),
                    message_types=EIP3009_TYPES, message_data=message)
                signature = account.sign_message(typed).signature.hex()
                if not signature.startswith('0x'):
                    signature = '0x' + signature
                if Account.recover_message(typed, signature=signature).lower() != account.address.lower():
                    raise ValueError
                payload = dict(authorization=auth, signature=signature)
            else:
                payload = self.signer.generate_eip3009_payload_atomic('USDC', req['amount'], req['payTo'],
                    chain_id=8453, token_address=req['asset'], valid_before=expiry,
                    requirement_hash=requirement_hash, idempotency_key=pid, now=now)
                validate_eip3009_payload(payload, expected_signer=self.signer.address,
                    chain_id=8453, token_address=req['asset'], asset='USDC',
                    atomic_amount=req['amount'], pay_to=req['payTo'], now=now,
                    max_valid_before=expiry, expected_nonce=nonce)
            envelope = dict(x402Version=2, accepted=req, payload=payload,
                            resource=op.required['resource'], extensions=op.required['extensions'])
            proof = base64.b64encode(jcs_canonical_bytes(envelope)).decode('ascii')
            if len(proof) > 16384:
                raise ValueError
            op.proof = proof
            op.state = 'PREPARED'
        except Exception:
            pass
        if op.proof is None:
            raise self._error('ACCESS_SIGNING_FAILED', op)

    def _observe(self, op, status, headers, body):
        """Keep receipt/accounting separate from the Origin body/status parser."""
        try:
            h = _headers(headers)
            envelope = _json(body)
        except Exception:
            envelope = {}
            h = _headers(headers)
        access = envelope.get('schema_version') == SCHEMA and envelope.get('purpose') == PURPOSE
        if op is not None:
            pid = op.terms.purchase_id
            if access and envelope.get('purchase_id', pid) != pid:
                raise self._error('ACCESS_CONFLICT', op)
            receipt = None
            if 'payment-response' in h:
                try:
                    candidate = _b64(h['payment-response'])
                    if (candidate.get('success') is True and candidate.get('network') == op.terms.network
                            and re.fullmatch('0x[0-9a-fA-F]{64}', candidate.get('transaction', ''))):
                        receipt = {k: candidate[k] for k in ('success', 'network', 'transaction')}
                except Exception:
                    pass
            paid = bool(receipt or (access and envelope.get('status') == 'PAID'))
            with self._lock:
                if paid and op.proof is not None:
                    self._spent.setdefault(pid, self._reserved.pop(pid, 10000))
                    op.state = 'PAID'
                snapshot = self._snapshots.setdefault(pid, {})
                if receipt:
                    snapshot['receipt'] = receipt
                if 'x-ln-access-quota' in h:
                    try:
                        quota = _b64(h['x-ln-access-quota'])
                        if quota.get('version') == 1 and quota.get('purchaseId', pid) == pid:
                            snapshot['quota'] = {k: quota[k] for k in ('freeRemaining', 'paidRemaining', 'resetAt')
                                                if k in quota and (quota[k] is None or
                                                    (k == 'resetAt' and isinstance(quota[k], str)) or
                                                    (type(quota[k]) is int and quota[k] >= 0))}
                    except Exception:
                        pass
                if access and envelope.get('status') == 'FAILED_FINAL' and op.state != 'PAID':
                    self._reserved.pop(pid, None)
                    op.state = 'FAILED_FINAL'
        if access:
            code = envelope.get('code')
            mapped = {'result_expired': 'ACCESS_RESULT_EXPIRED', 'result_unavailable': 'ACCESS_RESULT_UNAVAILABLE',
                      'failed_final': 'ACCESS_FAILED_FINAL', 'conflict': 'ACCESS_CONFLICT'}.get(code)
            if mapped == 'ACCESS_FAILED_FINAL' and (op is None or op.state != 'FAILED_FINAL'):
                mapped = 'ACCESS_PENDING'
            if mapped is None:
                mapped = 'ACCESS_PENDING' if status == 202 else 'ACCESS_UNAVAILABLE'
            retry = None
            try:
                retry = float(h.get('retry-after', ''))
                if not 0 <= retry <= 30:
                    retry = None
            except ValueError:
                pass
            raise self._error(mapped, op, retry)

    def exchange(self, *, method, url, headers, body, send, deadline, clock,
                 readonly=False, maximum_body=4 * 1024 * 1024):
        """send(extra_headers, remaining) uses the original pinned transport.

        At most initial exchange + one same-operation signed continuation.
        On re-entry, pending purchases go to the Edge before normal admission.
        """
        error = None
        try:
            return self._exchange(method, url, headers, body, send, deadline, clock, readonly, maximum_body)
        except AccessQuotaError as e:
            error = e.detached()
        # Drop the exception graph and all original request/proof local variables.
        method = url = headers = body = send = None
        raise error

    def _exchange(self, method, url, headers, body, send, deadline, clock, readonly, maximum_body):
        if not eligible(method, url):
            return send({}, max(0.0, deadline - clock()))
        if clock() >= deadline:
            raise self._error('ACCESS_PENDING')
        digest = request_digest(method, url, headers, body)
        with self._lock:
            op = self._operations.get(digest)
        read_id = self._readonly_purchase.get()
        if read_id is not None:
            if op is None or op.terms.purchase_id != read_id:
                raise self._error('ACCESS_CONFLICT')
            readonly = True
        # Serialize a known operation; a parallel first challenge may receive
        # another purchase ID, but installation below chooses one before signing.
        if op is None:
            raw = send({'X-LN-Claim-Recovery': '1'} if readonly else {}, max(0.0, deadline - clock()))
            status, rh, rb = raw
            if len(rb) > maximum_body:
                raise self._error('ACCESS_INVALID')
            candidate = _challenge(status, rh, rb, method, url, headers, body, self.network)
            if candidate is None:
                self._observe(None, status, rh, rb)
                return raw
            if readonly:
                raise self._error('ACCESS_PENDING')
            with self._lock:
                existing = self._purchases.get(candidate.terms.purchase_id)
                if existing and existing.digest != digest:
                    raise self._error('ACCESS_CONFLICT')
                op = self._operations.setdefault(digest, candidate)
                self._purchases.setdefault(op.terms.purchase_id, op)
        with op.lock:
            if op.result_error is not None:
                # A concurrent call may already hold this retired operation.
                # It must not send its proof again or silently become a new GET.
                raise self._error(op.result_error, op)
            if op.state == 'FAILED_FINAL':
                raise self._error('ACCESS_FAILED_FINAL', op)
            if op.state == 'SIGNING':
                raise self._error('ACCESS_SIGNING_FAILED', op)
            if op.proof is None and (readonly or not self.allow or self.signer is None
                                     or self._wall_time() >= op.payload['expires_at']):
                # Caller explicitly re-enters after reset; no automatic wait.
                reset = datetime.fromisoformat(op.terms.reset_at.replace('Z', '+00:00')).timestamp()
                if not readonly and (self._wall_time() >= reset or self._wall_time() >= op.payload['expires_at']) and clock() < deadline:
                    raw = send({}, deadline - clock())
                    new = _challenge(*raw, method, url, headers, body, self.network)
                    if new is None:
                        self._observe(None, *raw)
                        with self._lock:
                            self._operations.pop(digest, None)
                        return raw
                    # A new free-window challenge may replace only an unsigned op.
                    with self._lock:
                        self._purchases.pop(op.terms.purchase_id, None)
                        op.required, op.challenge, op.payload, op.terms = new.required, new.challenge, new.payload, new.terms
                        self._purchases[op.terms.purchase_id] = op
                raise self._error('ACCESS_REQUIRED', op)
            if not readonly:
                self._reserve_and_sign(op, deadline, clock)
            if clock() >= deadline:
                raise self._error('ACCESS_PENDING', op)
            extra = {'X-LN-Access-Challenge': op.challenge}
            if readonly:
                extra['X-LN-Access-Recovery'] = '1'
            else:
                extra['PAYMENT-SIGNATURE'] = op.proof
            try:
                op.state = 'PAID' if op.state == 'PAID' else 'PENDING'
                raw = send(extra, deadline - clock())
            except Exception:
                raw = None
            if raw is None:
                raise self._error('ACCESS_PENDING', op)
            if len(raw[2]) > maximum_body:
                raise self._error('ACCESS_PENDING', op)
            try:
                self._observe(op, *raw)
            except AccessQuotaError as error:
                if (method == 'GET' and op.state == 'PAID' and error.code in
                        {'ACCESS_RESULT_EXPIRED', 'ACCESS_RESULT_UNAVAILABLE'}):
                    # End only this GET's saved-result recovery. Keep the paid
                    # purchase, receipt and accounting; no new request here.
                    op.result_error = error.code
                    with self._lock:
                        if self._operations.get(digest) is op:
                            del self._operations[digest]
                raise
            # No new challenge or replacement nonce for an unresolved purchase.
            if raw[0] == 402 and op.state != 'PAID':
                raise self._error('ACCESS_PENDING', op)
            if op.state != 'PAID':
                raise self._error('ACCESS_PENDING', op)
            with self._lock:
                self._operations.pop(digest, None)
            return raw

    def finish_failed(self, purchase_id):
        """Explicitly start a new API operation only after FAILED_FINAL."""
        with self._lock:
            op = self._purchases.get(purchase_id)
            if op is None or op.state != 'FAILED_FINAL':
                raise AccessQuotaError('ACCESS_CONFLICT')
            if self._operations.get(op.digest) is op:
                del self._operations[op.digest]
