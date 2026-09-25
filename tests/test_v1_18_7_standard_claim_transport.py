"""DC eb015792 §4: real HTTPX/httpcore/pinning/parser, controlled I/O clock.

Only the resolved address and underlying SyncBackend socket/TLS stream are
synthetic. Client, exchange, pinned helper and HTTP parser are unchanged.
No external requests, real signatures, payments, or wall-clock sleeps.
"""
import copy
import hashlib
import json
import ssl
import httpcore
import pytest
from eth_account import Account
from test_v1_18_5_paid_service_trial_contract import wire
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2
from test_v1_18_5_paid_service_trial_accepted_address import address_lane, run_and_check
from ln_church_agent import paid_service_trial_transport as t
from ln_church_agent import paid_service_trial_journal as j
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient


@pytest.fixture(autouse=True)
def deterministic_synthetic_account(monkeypatch):
    # Public test seed, never a funded account. Keep baseline/candidate wire equal.
    monkeypatch.setattr(Account, 'create', lambda *a, **kw:
        Account.from_key(hashlib.sha256(b'public synthetic C2 fixture').digest()))


class WireServer:
    def __init__(self, monkeypatch, payload, plans, *, preparation=(0, 0, 0)):
        self.payload = payload
        self.plans = iter(plans)
        self.now = 0.0
        self.preparation = preparation
        self.requests = []
        self.allocations = 0
        self.original = None
        self.events = []
        self.connects = []
        self.sni = []
        self.response_hashes = []
        monkeypatch.setattr(httpcore.SyncBackend, 'connect_tcp', self.connect_tcp)

    def clock(self):
        return self.now

    def resolver(self, host, port):
        assert (host, port) == (t.PUBLIC_API_HOST, 443)
        self.now += self.preparation[0]
        return ['8.8.8.8']

    def wait(self, stage, delay, timeout):
        assert 0 < timeout <= 20
        elapsed = min(delay, timeout)
        self.now += elapsed
        self.events.append(dict(stage=stage, elapsed=elapsed, timeout=timeout, at=self.now))
        if delay > timeout:
            error = httpcore.ReadTimeout if stage.endswith('read') else httpcore.ConnectTimeout
            raise error('SYNTHETIC_PRIVATE')

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        assert host in ('8.8.8.8', b'8.8.8.8') and port == 443 and local_address is None
        assert timeout <= 5
        self.connects.append((str(host), port))
        self.wait('connect', self.preparation[1], timeout)
        return WireStream(self, next(self.plans))

    def client(self, directory, version='v2'):
        self.directory, self.version = directory, version
        return PaidServiceTrialTaskClient(version=version, claim_directory=directory,
            transport=t.PaidServiceTrialTransport(version=version, resolver=self.resolver,
                                                   monotonic=self.clock))

    def observe(self):
        return dict(elapsed=self.now, total_budget_per_attempt=20, events=self.events,
                    api_attempts=len(self.requests), new_claims=self.allocations,
                    response_sha256=self.response_hashes, live_requests=0, live_payments=0)


class WireStream:
    def __init__(self, server, plan):
        self.server = server
        self.plan = plan
        self.sent = bytearray()
        self.chunks = None

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        assert isinstance(ssl_context, ssl.SSLContext)
        assert ssl_context.check_hostname and ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert server_hostname in (t.PUBLIC_API_HOST, t.PUBLIC_API_HOST.encode())
        assert timeout <= 5
        self.server.sni.append(str(server_hostname))
        self.server.wait('tls', self.server.preparation[2], timeout)
        return self

    def get_extra_info(self, info):
        return None

    def write(self, buffer, timeout=None):
        assert 0 < timeout <= 10
        self.sent.extend(buffer)

    def read(self, max_bytes, timeout=None):
        s = self.server
        if self.chunks is None:
            head, body = bytes(self.sent).split(b'\r\n\r\n', 1)
            lines = head.split(b'\r\n')
            assert lines[0] == ('POST /api/agent/tasks/' + s.payload['task_id'] + '/claim HTTP/1.1').encode()
            headers = dict(line.split(b': ', 1) for line in lines[1:])
            lower = {k.lower(): v for k, v in headers.items()}
            assert lower[b'host'] == t.PUBLIC_API_HOST.encode()
            assert lower[b'accept-encoding'] == b'identity'
            assert lower[b'user-agent'] == t.USER_AGENT.encode()
            assert lower[b'content-type'] == b'application/json'
            assert not ({b'authorization', b'cookie', b'payment-signature'} & lower.keys())
            assert len(body) == int(lower[b'content-length'])
            identity = (lines[0], lower[b'idempotency-key'], body)
            saved = j._ClaimRequest(s.directory, s.version, s.payload['task_id'], 'original-key').read()
            assert saved['state'] == 'UNKNOWN' and saved['body'].encode() == body
            assert saved['idempotency_key'].encode() == lower[b'idempotency-key']
            s.requests.append(identity)
            if s.original is None:
                s.original = identity
                s.allocations += 1
            assert identity == s.original
            payload = copy.deepcopy(s.payload)
            if self.plan.get('dto'):
                payload['unexpected'] = 'SYNTHETIC_PRIVATE'
            response = self.plan.get('body', json.dumps(payload).encode())
            s.response_hashes.append(hashlib.sha256(response).hexdigest())
            response_head = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(response)).encode() + b'\r\n\r\n'
            self.chunks = [(self.plan.get('head_delay', 0), response_head)]
            if self.plan.get('split'):
                self.chunks += [(9, response[:1]), (9, response[1:])]
            else:
                self.chunks += [(self.plan.get('body_delay', 0), response)]
            self.stage = 'head-read'
        if not self.chunks:
            return b''
        delay, value = self.chunks.pop(0)
        s.wait(self.stage, delay, timeout)
        if self.plan.get('lost') and self.stage == 'head-read':
            return b''
        self.stage = 'body-read'
        assert len(value) <= max_bytes
        return value

    def close(self):
        pass


def start(server, directory, version='v2'):
    return server.client(directory, version).claim_task(server.payload['task_id'], 'synthetic-agent',
        server.payload['reward_address'], idempotency_key='original-key')


@pytest.mark.parametrize('plan,preparation', [
    ({}, (0, 0, 0)),
    ({'head_delay': 12}, (0, 0, 0)),
    ({'body_delay': 12}, (0, 0, 0)),
    ({'head_delay': 12}, (2, 1, 1)),
    ({'head_delay': 19.5}, (0, 0, 0)),
])
def test_valid_response_within_total_budget(wire_v2, tmp_path, monkeypatch, plan, preparation, record_property):
    server = WireServer(monkeypatch, wire_v2.claim, [plan], preparation=preparation)
    try:
        claim = start(server, tmp_path)
    except t.PaidServiceTrialTransportError as error:
        record_property('failure', json.dumps(dict(code=error.code, status=error.status_code,
            request_bytes_sent=error.request_bytes_sent)))
        raise
    finally:
        record_property('transport', json.dumps(server.observe()))
    assert claim._private_payload() == wire_v2.claim
    assert server.allocations == len(server.requests) == 1
    assert server.now < 20
    assert j._ClaimRequest(tmp_path, 'v2', claim.task_id, 'original-key').read()['state'] == 'READY'
    assert server.client(tmp_path).recover_claim(claim.task_id, idempotency_key='original-key')._private_payload() == wire_v2.claim
    assert len(server.requests) == 1


@pytest.mark.parametrize('plan,status,elapsed', [
    ({'head_delay': 21}, None, 20),
    ({'head_delay': 4, 'body_delay': 17}, 200, 20),
    ({'head_delay': 3, 'split': True}, 200, 20),
    ({'body': b'{SYNTHETIC_PRIVATE'}, 200, 0),
    ({'dto': True}, 200, 0),
    ({'lost': True}, None, 0),
])
def test_unknown_is_finite_and_standard_recovery_uses_same_request(wire_v2, tmp_path, monkeypatch, plan, status, elapsed, record_property):
    server = WireServer(monkeypatch, wire_v2.claim, [plan, {}])
    with pytest.raises(t.PaidServiceTrialTransportError) as error:
        start(server, tmp_path)
    e = error.value
    record_property('first_attempt', json.dumps(dict(server.observe(), status=e.status_code, code=e.code)))
    assert e.code == 'CLAIM_OUTCOME_UNKNOWN' and e.status_code == status
    assert e.request_bytes_sent is True and e.__cause__ is None and e.__context__ is None
    assert e.public_error_code is None and e.request_id is None and e.reason is None
    assert server.now == elapsed and len(server.requests) == server.allocations == 1
    record = j._ClaimRequest(tmp_path, 'v2', wire_v2.claim['task_id'], 'original-key')
    assert record.read()['state'] == 'UNKNOWN'
    claim = server.client(tmp_path).recover_claim(wire_v2.claim['task_id'], idempotency_key='original-key')
    assert claim._private_payload() == wire_v2.claim
    assert record.read()['state'] == 'READY' and len(server.requests) == 2 and server.allocations == 1
    record_property('transport', json.dumps(dict(server.observe(), recovered=True)))


@pytest.mark.parametrize('mode', ['initial', 'lost', 'twice-unknown'])
def test_standard_claim_recovery_to_existing_executor(address_lane, monkeypatch, mode, record_property):
    lane = address_lane
    # Only remove this fixture's unused pre-created files, before initial Claim.
    lane.journal.path.unlink()
    lane.journal.credential_path.unlink()
    plans = ([{'lost': True}] if mode == 'lost' else
             [{'head_delay': 21}, {'head_delay': 21}] if mode == 'twice-unknown' else [])
    failures = len(plans)
    plans.append({'head_delay': 12})
    server = WireServer(monkeypatch, lane.w.claim, plans)
    for attempt in range(failures):
        with pytest.raises(t.PaidServiceTrialTransportError):
            if attempt == 0:
                start(server, lane.tmp_path, lane.version)
            else:
                server.client(lane.tmp_path, lane.version).recover_claim(lane.w.claim['task_id'], idempotency_key='original-key')
        assert lane.http.paid == 0 and not lane.signer.calls
    try:
        claim = (start(server, lane.tmp_path, lane.version) if not failures else
                 server.client(lane.tmp_path, lane.version).recover_claim(lane.w.claim['task_id'], idempotency_key='original-key'))
    finally:
        record_property('claim_transport', json.dumps(server.observe()))
    assert claim._private_payload() == lane.w.claim
    assert len(server.requests) == failures + 1 and server.allocations == 1
    lane.w.credential = claim
    lane.journal = j.PaidServiceTrialJournal(lane.tmp_path, claim)
    run_and_check(lane, 'standard-api-' + mode)
    record_property('transport', json.dumps(dict(server.observe(), paid_sends=lane.http.paid,
        restart_extra_paid_sends=0, original_execution_and_times=True, unpaid_while_unknown=True)))
