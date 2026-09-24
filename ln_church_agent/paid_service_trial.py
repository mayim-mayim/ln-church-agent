"""One claim-bound external purchase, followed by its identifying report."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from decimal import Decimal
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

from . import paid_service_trial_contract as c
from .paid_service_trial_models import PaidServiceTrialClaim, PurchaseIdentity, FrozenPaidServiceTrialReport, parse_claim
from .paid_service_trial_network import PaidServiceTrialHTTPS, BaseSealedBlockGuard, _current_terms_context, _current_v2_terms_context, PaidServiceTrialTermsError
from .models import PaymentPolicy, _PaymentOperation
from .crypto.evm import derive_eip3009_requirement_nonce, validate_eip3009_payload
from .task_journal import JournalError, JournalPersistenceError
from .paid_service_trial_transport import PaidServiceTrialError


@dataclass(frozen=True)
class PaidServiceTrialExecution:
    state: str
    reason: Any = None
    report: Any = field(default=None,repr=False)
    completion: Any = None
    http_outcome: str = 'NOT_OBSERVED'
    http_status: Any = None


class PaidServiceTrialExecutor:
    def __init__(self, *, signer: Any, policy: PaymentPolicy, client: Any,
                 base_rpc_url: str='https://mainnet.base.org', http: Any=None,
                 block_guard: Any=None, wall_time: Any=time.time) -> None:
        if not isinstance(policy,PaymentPolicy):
            raise ValueError('Explicit PaymentPolicy required.')
        self._signer=signer;self._policy=policy;self._client=client
        self._http=http or PaidServiceTrialHTTPS()
        self._guard=block_guard or BaseSealedBlockGuard(base_rpc_url=base_rpc_url)
        self._wall_time=wall_time

    def __repr__(self) -> str:
        return 'PaidServiceTrialExecutor(<explicit signer and policy>)'

    def _reserve_policy(self,claim: PaidServiceTrialClaim,operation_id: str) -> Any:
        p=self._policy;host=urlsplit(c.target_url(claim)).hostname
        amount=Decimal(claim.purchase_terms.requirements.amount)/Decimal(1000000)
        with p._session_spend_lock:
            entries=p._session_operations.setdefault(claim.task_type,{})
            existing=entries.get(operation_id)
            if existing is not None:
                return existing
            maximum=Decimal(str(p.max_spend_per_tx_usd));session=Decimal(str(p.max_spend_per_session_usd))
            spent=p._session_baseline_usd+p._budget_total('confirmed')+p._budget_total('reserved')
            if (not maximum.is_finite() or not session.is_finite() or maximum<amount or spent+amount>session
                    or 'exact' not in p.allowed_schemes or 'USDC' not in p.allowed_assets
                    or (p.allowed_networks is not None and c.NETWORK not in p.allowed_networks)
                    or host in p.blocked_hosts or (p.allowed_hosts is not None and host not in p.allowed_hosts)):
                raise ValueError('Purchase denied by PaymentPolicy.')
            op=_PaymentOperation(amount=amount,budget_state='reserved',phase='reserved',owner=operation_id)
            entries[operation_id]=op;p._session_ledger_version+=1
            return op

    def execute(self,claim: PaidServiceTrialClaim,*,journal: Any) -> PaidServiceTrialExecution:
        try:
            return self._execute(claim,journal=journal)
        except (JournalError,JournalPersistenceError,PaidServiceTrialError,PaidServiceTrialTermsError):
            raise
        except Exception:
            pass
        raise ValueError('Paid Service Trial execution stopped before further action.')

    def _execute(self,claim: PaidServiceTrialClaim,*,journal: Any) -> PaidServiceTrialExecution:
        claim=parse_claim(claim)
        version=c.version_of(claim)
        journal.require_binding(claim)
        with journal.operation_guard():
            saved=journal.snapshot()
            if saved['report'] is not None:
                if not saved['paid_dispatch_reserved']:
                    return PaidServiceTrialExecution('NO_DISPATCH','prepared_without_dispatch')
                report=journal.load_report()
            else:
                bundle=c.load_contract_bundle(version)
                if claim.task_definition_digest!=bundle['manifest']['task_definition_digest']:
                    raise ValueError('Invalid Definition identity.')
                if c.address(self._signer.address)!=claim.reward_address:
                    raise ValueError('Claim reward wallet differs from signer.')
                if int(self._wall_time()*1000)>=c.instant_ms(claim.report_deadline):
                    return PaidServiceTrialExecution('NO_DISPATCH','report_deadline')
                request=c.target_request(claim)
                response=self._http.fetch(request)
                current=(_current_terms_context(response,claim.purchase_terms) if version=='v1'
                         else _current_v2_terms_context(response,claim.purchase_terms,request))
                terms=current.terms
                if not self._guard.ready(claim.purchase_block_timestamp_exclusive_min):
                    return PaidServiceTrialExecution('NO_DISPATCH','sealed_block_unavailable')
                if int(self._wall_time()*1000)>=c.instant_ms(claim.report_deadline):
                    return PaidServiceTrialExecution('NO_DISPATCH','report_deadline')
                operation_id=saved['operation_id']
                budget=self._reserve_policy(claim,operation_id)
                fenced=False
                try:
                    now=int(self._wall_time());req=terms.requirements
                    expiry=now+min(300,req.maxTimeoutSeconds)
                    requirement_hash='sha256:'+c.version_digest(dict(claim=claim.model_dump(mode='json'),operation_id=operation_id),version)
                    nonce=derive_eip3009_requirement_nonce(requirement_hash,operation_id)
                    payload=self._signer.generate_eip3009_payload_atomic('USDC',req.amount,req.payTo,
                        chain_id=8453,token_address=c.ASSET,valid_before=expiry,
                        requirement_hash=requirement_hash,idempotency_key=operation_id,now=now)
                    validate_eip3009_payload(payload,expected_signer=claim.reward_address,chain_id=8453,
                        token_address=c.ASSET,asset='USDC',atomic_amount=req.amount,pay_to=req.payTo,
                        now=now,max_valid_before=expiry,expected_nonce=nonce)
                    auth=payload['authorization']
                    if auth['validBefore']!=str(expiry):
                        raise ValueError('Invalid signed validity.')
                    purchase=PurchaseIdentity(network=c.NETWORK,asset=c.ASSET,payer=c.address(auth['from']),
                        authorization_nonce=c.hash32(auth['nonce']),payTo=c.address(auth['to']),amount=auth['value'],
                        validAfter=auth['validAfter'],validBefore=auth['validBefore'])
                    accepted=dict(req.wire(),asset=current.asset,payTo=current.pay_to)
                    envelope=dict(x402Version=2,accepted=accepted,payload=payload,resource=dict(url=c.target_url(claim)))
                    signed=c.version_bytes(envelope,version)
                    encoded=base64.b64encode(signed).decode('ascii')
                    if len(encoded)>16384:
                        raise ValueError('Payment header too large.')
                    core={k:getattr(claim,k) for k in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest','execution_id')}
                    if version=='v2':
                        core.update(request_digest=claim.request_digest,purchase_terms_digest=claim.purchase_terms_digest)
                    core.update(schema_version='ln_church.task_completion.paid_service_trial.'+version,
                                submission_id='sub_'+uuid.uuid4().hex,purchase=purchase.model_dump(mode='json'))
                    report=FrozenPaidServiceTrialReport.from_dict(core)
                    try:
                        if int(self._wall_time()*1000)>=c.instant_ms(claim.report_deadline) or int(self._wall_time())>=expiry:
                            return PaidServiceTrialExecution('NO_DISPATCH','report_deadline')
                        if version=='v2':
                            # Same frozen R and selected conditions after signing.
                            # Only the final seller spelling changes the envelope.
                            current=_current_v2_terms_context(self._http.fetch(request),terms,request)
                            accepted.update(asset=current.asset,payTo=current.pay_to)
                            journal.require_binding(claim)
                            if int(self._wall_time())>=expiry or int(self._wall_time()*1000)>=c.instant_ms(claim.report_deadline):
                                return PaidServiceTrialExecution('NO_DISPATCH','report_deadline')
                        signed=c.version_bytes(envelope,version)
                        encoded=base64.b64encode(signed).decode('ascii')
                    finally:
                        # Persist the final envelope before reserving/sending. A
                        # failed final check still leaves the signed operation
                        # PREPARED and non-sendable on re-entry, as before.
                        journal.prepare(report,c.version_digest(envelope,version))
                    journal.reserve_paid_dispatch();fenced=True
                    outcome='UNKNOWN';status=None;locator=None
                    try:
                        response=self._http.fetch(request,payment_signature=encoded)
                        if type(response.status_code) is int and 100<=response.status_code<=599:
                            status=response.status_code
                        outcome='RESPONSE_RECEIVED' if response.complete and status is not None else 'FAILED'
                        locator=c.payment_response_locator(response.headers,payer=claim.reward_address)
                    except Exception:
                        # Lost delivery is never permission for another paid GET.
                        pass
                    finally:
                        payload=None;envelope=None;encoded=None;signed=None
                    journal.save_outcome(outcome,status,locator)
                    report=journal.load_report()
                finally:
                    if not fenced:
                        with self._policy._session_spend_lock:
                            self._policy._session_operations[claim.task_type].pop(operation_id,None)
            saved=journal.snapshot()
        # Release the stable purchase lock before the same journal's bounded
        # completion cycle. The economic fence is already durable.
        completion=self._client.complete_task(claim,report,journal=journal)
        return PaidServiceTrialExecution('REPORTED',report=report,completion=completion,
                                        http_outcome=saved['http_outcome'],http_status=saved['http_status'])


def export_purchase_import_descriptor(endpoint: Any, transaction_hash: str, purchase_terms: Any,
                                      purchase: Any=None, *, import_request_id: Any=None, version: str='v2') -> dict:
    """Explicit nonsecret import request; performs no I/O, signing or purchase.

    Persist this descriptor before submitting it to the Requester import flow.
    Reuse its UUID/bytes for every retry. An absent purchase allows Tx-only
    import, including supported contract-wallet payments.
    """
    from .paid_service_trial_models import PurchaseTerms
    c.validate_version(version)
    selected=PurchaseTerms.model_validate(purchase_terms)
    request_id=str(uuid.uuid4()) if import_request_id is None else import_request_id
    if type(request_id) is not str or str(uuid.UUID(request_id,version=4))!=request_id:
        raise ValueError('Invalid import request ID.')
    if version=='v1':
        result=dict(schema_version='ln_church.paid_service_trial_sample_import_request.v1',
                    import_request_id=request_id,endpoint=c.endpoint(endpoint),
                    purchase_terms_digest=c.digest(selected.requirements.wire()),transaction_hash=c.hash32(transaction_hash))
    else:
        request=c.validate_request(endpoint)
        result=dict(schema_version='ln_church.paid_service_trial_sample_import_request.v2',
                    import_request_id=request_id,request=request,request_digest=c.v2_digest(request),
                    purchase_terms=selected.wire(),purchase_terms_digest=c.purchase_terms_digest(request,selected),
                    transaction_hash=c.hash32(transaction_hash))
    if purchase is not None:
        identity=PurchaseIdentity.model_validate(purchase)
        req=selected.requirements
        if identity.payTo!=req.payTo or identity.amount!=req.amount:
            raise ValueError('Purchase identity does not match selected terms.')
        result['purchase']=identity.model_dump(mode='json')
    c.version_bytes(result,version)
    return result
