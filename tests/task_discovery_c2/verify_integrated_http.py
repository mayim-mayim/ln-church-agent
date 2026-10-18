"""Run fixed integration server unchanged; bind real SDK through test-only HTTP.

Usage: PYTHONPATH=<SDK source or isolated wheel>:<this directory> python
  verify_integrated_http.py <fixed Backend workspace> <evidence output>
No public URL is contacted. Only the private exchange maps path/query to loopback.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
import signal
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, ProxyHandler, Request

from ln_church_agent import AgentTaskClient, TaskDiscoveryPage
from ln_church_agent.access_quota import AccessQuotaPolicy
from ln_church_agent.endpoint_choice_reason_models import EndpointChoiceTask
from ln_church_agent.task_transport import TaskError, TaskTransport
from wire_inputs import FIXTURES_BYTES, QUOTA_BYTES, SCHEMA_BYTES
from wire_support import run_cli

COMMIT = '4cacfa79501d384fec0eac29cb3fea1ccf3c47be'
ORIGIN = 'https://kari.mayim-mayim.com'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('backend', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root, output = args.backend.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    origin = 'http://127.0.0.1:' + str(port)
    opener = build_opener(ProxyHandler({}))
    observations, runs = [], []

    def request(path, scenario='mixed', production=None):
        assert path.startswith('/') and not path.startswith('//')
        req = Request(origin + path, headers={'X-TD-Scenario': scenario}, method='GET')
        try:
            response = opener.open(req, timeout=15)
        except HTTPError as e:
            response = e
        with response:
            raw = response.read()
            headers = dict(response.headers)
            status = response.status
        row = dict(local_url=origin+path, production_url=production,
                   method='GET', scenario=scenario, status=status,
                   headers=headers, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if headers.get('Content-Type', headers.get('content-type', '')).startswith('application/json'):
            row['value'] = json.loads(raw)
        observations.append(row)
        return status, headers, raw

    class Live:
        def __init__(self, scenario='mixed'):
            self.scenario, self.calls = scenario, []
            self.policy = AccessQuotaPolicy()
            self.transport = TaskTransport(
                _resolver=lambda *_: ['8.8.8.8'], _exchange=self.send,
                _sleep=lambda _: (_ for _ in ()).throw(AssertionError('Unexpected retry')),
                access_quota=self.policy)
            self.client = AgentTaskClient(_transport=self.transport)

        def send(self, **kw):
            assert kw['method'] == 'GET' and kw['body'] is None
            assert kw['claim_token'] is None and not kw.get('access_headers')
            parsed = urlsplit(kw['url'])
            assert parsed.scheme+'://'+parsed.netloc == ORIGIN and not parsed.query
            suffix = '?' + urlencode(kw['params']) if kw['params'] else ''
            status, headers, raw = request(parsed.path+suffix, self.scenario, kw['url']+suffix)
            assert {k.lower():v for k,v in headers.items()}['x-td-execution'] == 'actual-taskget-isolated-storage'
            self.calls.append(observations[-1])
            return status, headers, raw

    log_path = output/'server.log'
    result = dict(backend_commit=COMMIT, backend_tree='86f2326f96b66c817fd8c3ec8e8cbf70837c382b',
                  command=['node', 'tests/post-v1814/task-discovery-integrated-c1/server.mjs'],
                  cwd=str(root), origin=origin, observations=observations, cli_runs=runs)
    with log_path.open('w') as log:
        proc = subprocess.Popen(result['command'], cwd=root,
                                env=dict(os.environ, TD_INTEGRATED_PORT=str(port)),
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+15
            while 'TD_INTEGRATED_READY ' not in log_path.read_text():
                assert proc.poll() is None, 'Fixed server exited before ready'
                assert time.monotonic() < deadline, 'Fixed server did not become ready'
                time.sleep(0.05)
            marker = next(s for s in log_path.read_text().splitlines() if s.startswith('TD_INTEGRATED_READY '))
            result['ready'] = json.loads(marker.split(' ', 1)[1])
            _, _, raw = request('/__identity')
            identity = json.loads(raw)
            assert identity['checkout_head'] == COMMIT and identity == {k:v for k,v in result['ready'].items() if k != 'origin'}
            result['identity'] = identity

            # These are separately labeled byte replays, not handler tests.
            for path, expected in [('/__wire/fixtures.json', FIXTURES_BYTES),
                                   ('/__wire/quota-402.json', QUOTA_BYTES),
                                   ('/__wire/schema.json', SCHEMA_BYTES)]:
                status, headers, raw = request(path)
                assert status == 200 and raw == expected
                assert 'not handler execution' in {k.lower():v for k,v in headers.items()}['x-td-execution']

            live = Live()
            full = live.client.discover_tasks()
            assert len(live.calls) == 1 and full.page_scope == 'initial'
            assert {t.task_definition_version for t in full.tasks} == {'2.0.0', '2.1.0'}
            assert TaskDiscoveryPage.model_validate(live.calls[-1]['value']) == full
            first = live.client.discover_tasks(limit=1)
            assert first.next_cursor and len(first.tasks) == 1
            second = live.client.discover_tasks(limit=1, cursor=first.next_cursor)
            assert second.page_scope == 'continuation' and second.tasks[0].task_id != first.tasks[0].task_id
            fresh = live.client.discover_tasks(limit=1)
            assert fresh.page_scope == 'initial' and fresh == first
            assert all('task_type=' not in x['production_url'] and 'task_schema_version=' not in x['production_url'] for x in live.calls)
            result['pages'] = dict(full=full.model_dump(mode='json'), first=first.model_dump(mode='json'),
                                   continuation=second.model_dump(mode='json'), fresh=fresh.model_dump(mode='json'))
            result['details'] = []
            for version in ('2.0.0', '2.1.0'):
                candidate = next(t for t in full.tasks if t.task_definition_version == version)
                url = urlsplit(candidate.detail_url)
                status, _, raw = request(url.path+'?'+url.query, production=candidate.detail_url)
                assert status == 200
                detail = EndpointChoiceTask.model_validate(json.loads(raw))
                assert (detail.task_id, detail.task_type, detail.task_definition_version,
                        detail.task_definition_digest, detail.schema_version, detail.definition_url) == (
                        candidate.task_id, candidate.task_type, candidate.task_definition_version,
                        candidate.task_definition_digest, candidate.task_schema_version, candidate.definition_url)
                status, _, raw = request(urlsplit(candidate.definition_url).path, production=candidate.definition_url)
                assert status == 200 and raw.startswith(b'#')
                relative = 'frontend'+urlsplit(candidate.definition_url).path
                assert raw == (root/relative).read_bytes()
                result['details'].append(dict(version=version, candidate=candidate.model_dump(mode='json'),
                                              detail=detail.model_dump(mode='json'), guide_path=relative,
                                              guide_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()))

            for scenario, kwargs in [('mixed', {}), ('mixed', dict(limit=1)),
                                     ('mixed', dict(limit=1, cursor=first.next_cursor)),
                                     ('uninitialized', {})]:
                for mode in (False, True):
                    ex = Live(scenario)
                    row = run_cli(ex.client, kwargs, mode)
                    row.update(scenario=scenario, calls=len(ex.calls))
                    assert len(ex.calls) == 1
                    if scenario == 'uninitialized':
                        assert row['exitcode'] == 2 and row['stdout'] == ''
                        assert 'No candidate count was obtained' in row['stderr']
                    else:
                        assert row['exitcode'] == 0 and row['stderr'] == ''
                        if mode:
                            assert json.loads(row['stdout']) == ex.calls[-1]['value']
                        else:
                            for t in ex.calls[-1]['value']['tasks']:
                                assert t['detail_url'] in row['stdout'] and t['definition_url'] in row['stdout']
                    runs.append(row)
            unavailable = Live('uninitialized')
            try:
                unavailable.client.discover_tasks()
                raise AssertionError('503 became success')
            except TaskError as e:
                assert e.status_code == 503 and len(unavailable.calls) == 1
                result['uninitialized'] = dict(code=e.code, status=e.status_code)

            # Exact invalid SDK queries never send; raw HTTP errors do execute.
            result['local_invalid'] = []
            for kwargs in [dict(limit=51), dict(cursor='td1.bad')]:
                ex = Live()
                try:
                    ex.client.discover_tasks(**kwargs)
                    raise AssertionError('Invalid local query sent')
                except TaskError as e:
                    assert e.request_bytes_sent is False and ex.calls == []
                    result['local_invalid'].append(dict(kwargs=kwargs, code=e.code, network_calls=0))
            for suffix in ('?limit=51', '?cursor=td1.bad'):
                status, headers, _ = request('/api/agent/tasks'+suffix)
                assert status == 400 and {k.lower():v for k,v in headers.items()}['x-td-execution'] == 'actual-taskget-isolated-storage'
            # Fixed server seeds only full legacy rows without legacy GSI
            # catalog entries. Its real old list is empty. Supply an existing-
            # format valid cursor explicitly; do not invent a returned cursor.
            old = Live()
            old_first = old.client.list_tasks(limit=1)
            key = dict(PK='TASK#task_full_0', SK='TASK', GSI1PK='TASK_STATUS#OPEN',
                       GSI1SK=identity['clock']+'#task_full_0')
            old_cursor = base64.urlsafe_b64encode(json.dumps(key, separators=(',', ':')).encode()).rstrip(b'=').decode()
            old_next = old.client.list_tasks(limit=1, cursor=old_cursor)
            assert old_first.tasks == old_next.tasks == []
            assert old_first.next_cursor is old_next.next_cursor is None
            assert all(x['production_url'].find('task_type=payment_surface_discovery.v1') >= 0 for x in old.calls)
            result['legacy'] = dict(first=old_first.model_dump(mode='json'), continuation=old_next.model_dump(mode='json'),
                                    calls=[x['production_url'] for x in old.calls], supplied_cursor=old_cursor,
                                    cursor_source='Constructed valid old key per fixed Lambda_TaskGet decodeListCursor; no returned old cursor exists in this empty catalog')
            assert old_cursor.startswith('td1.') is False
            _, _, raw = request('/__trace')
            result['handler_trace'] = json.loads(raw)
            trace = result['handler_trace']['requests']
            assert trace and all(x['execution'].startswith('actual TaskGet handler') for x in trace)
            assert any(x['status'] == 503 for x in trace) and any(x['status'] == 400 for x in trace)
            for row in trace:
                if row['status'] == 200 and row['scenario'] == 'mixed' and row['path'].startswith('/api/agent/tasks?limit=') and 'task_type=' not in row['path']:
                    assert [x['operation'] for x in row['db']] == ['Get', 'Query']
            result['modules'] = {n:str(Path(m.__file__).resolve()) for n,m in sys.modules.items()
                                 if (n == 'ln_church_agent' or n.startswith('ln_church_agent.')) and getattr(m, '__file__', None)}
            result['version'] = importlib.metadata.version('ln-church-agent')
            result['result'] = 'IMPLEMENTATION_SELF_CHECK_PASS'
            result['boundaries'] = 'Real TaskGet over loopback; actual Choice2.0/2.1 lifecycle and in-memory conditional stores, synthetic provider. Twelve-tuple and quota files are separately labeled replay. No public HTTP, Claim, purchase, signing or payment.'
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                result['server_exitcode'] = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill();proc.wait();raise AssertionError('Fixed server failed graceful stop')
            result['stop_signal'] = 'SIGTERM'
            assert result['server_exitcode'] == 0
            (output/'HTTP_RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    assert 'result' in result
    print(json.dumps(dict(result=result['result'], requests=len(observations), handler_requests=len(result['handler_trace']['requests']),
                         cli_runs=len(runs), version=result['version'], server_exitcode=result['server_exitcode'])))


if __name__ == '__main__':
    main()
