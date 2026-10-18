"""Minimal c3 SDK read against frozen b0d1b7bb actual TaskGet over loopback.

Run with SDK source or an isolated c3 wheel on PYTHONPATH, plus c2/c3 tests.
Arguments: <fixed Backend workspace> <output directory>.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.metadata
import json
import os
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, ProxyHandler, Request

from ln_church_agent import AgentTaskClient, TaskDiscoveryPage
from ln_church_agent.access_quota import AccessQuotaPolicy
from ln_church_agent.task_transport import TaskTransport
from wire_support import run_cli
from formal_identities import IDENTITIES

COMMIT = 'b0d1b7bba86b88033bd7e3c5ca1ade9d230b0aa0'
ORIGIN = 'https://kari.mayim-mayim.com'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('backend', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    root, out = args.backend.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    origin = 'http://127.0.0.1:'+str(port)
    opener = build_opener(ProxyHandler({}))
    calls = []

    def get(path):
        with opener.open(Request(origin+path, method='GET', headers={'X-TD-Scenario':'mixed'}), timeout=10) as r:
            return r.status, dict(r.headers), r.read()

    def exchange(**kw):
        assert kw['method'] == 'GET' and kw['body'] is None
        assert kw['claim_token'] is None and not kw.get('access_headers')
        u = urlsplit(kw['url'])
        assert u.scheme+'://'+u.netloc == ORIGIN
        assert u.path == '/api/agent/tasks' and set(kw['params']) == {'limit'}
        path = u.path+'?'+urlencode(kw['params'])
        status, headers, raw = get(path)
        assert {k.lower():v for k,v in headers.items()}['x-td-execution'] == 'actual-taskget-isolated-storage'
        calls.append(dict(public_url=kw['url']+'?'+urlencode(kw['params']), local_url=origin+path,
                          status=status, headers=headers, value=json.loads(raw),
                          bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        return status, headers, raw

    def client():
        policy = AccessQuotaPolicy()
        transport = TaskTransport(_resolver=lambda *_:['8.8.8.8'], _exchange=exchange,
            _sleep=lambda _: (_ for _ in ()).throw(AssertionError('Unexpected retry')),
            access_quota=policy)
        return AgentTaskClient(_transport=transport), policy

    result = dict(backend_commit=COMMIT, backend_tree='45c9a79e5249874760389db7b086ccf0db71b82d',
                  command=['node', 'tests/post-v1814/task-discovery-ui-c2/server.mjs'],
                  origin=origin, requests=calls)
    log_path = out/'server.log'
    with log_path.open('w') as log:
        proc = subprocess.Popen(result['command'], cwd=root,
            env=dict(os.environ, TD_INTEGRATED_PORT=str(port)), stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+15
            while 'TD_C2_READY ' not in log_path.read_text():
                assert proc.poll() is None and time.monotonic() < deadline
                time.sleep(0.05)
            lines = log_path.read_text().splitlines()
            result['ready'] = json.loads(next(s for s in lines if s.startswith('TD_INTEGRATED_READY ')).split(' ',1)[1])
            result['c2_ready'] = json.loads(next(s for s in lines if s.startswith('TD_C2_READY ')).split(' ',1)[1])
            _, _, raw = get('/__identity')
            identity = json.loads(raw)
            assert identity == result['ready'] and identity['checkout_head'] == COMMIT
            result['identity'] = identity
            c, policy = client()
            try:
                page = c.discover_tasks()
                assert len(calls) == 1
                assert page.model_dump(mode='json') == calls[-1]['value']
                assert TaskDiscoveryPage.model_validate(calls[-1]['value']) == page
                assert {t.task_definition_version for t in page.tasks} == {'2.0.0', '2.1.0'}
                for t in page.tasks:
                    a = next(a for a in IDENTITIES if (a['task_type'],a['version']) == (t.task_type,t.task_definition_version))
                    assert (t.task_schema_version,t.task_definition_digest) == (a['schema'],a['digest'])
                assert policy.reserved_atomic == policy.spent_atomic == 0
            finally:
                c.close()
            c, policy = client()
            row = run_cli(c, json_mode=True)
            assert row['exitcode'] == 0 and row['stderr'] == '' and len(calls) == 2
            assert json.loads(row['stdout']) == calls[-1]['value']
            assert policy.reserved_atomic == policy.spent_atomic == 0
            result['CLI_json'] = row
            _, _, raw = get('/__trace')
            result['trace'] = json.loads(raw)
            assert len(result['trace']['requests']) == 2
            for t in result['trace']['requests']:
                assert t['status'] == 200 and t['execution'].startswith('actual TaskGet handler')
                assert [d['operation'] for d in t['db']] == ['Get','Query']
            result['version'] = importlib.metadata.version('ln-church-agent')
            assert result['version'] == '1.18.15'
            result['modules'] = {n:str(Path(m.__file__).resolve()) for n,m in sys.modules.items()
                if (n == 'ln_church_agent' or n.startswith('ln_church_agent.')) and getattr(m,'__file__',None)}
            result['result'] = 'IMPLEMENTATION_SELF_CHECK_PASS'
            result['boundary'] = 'Actual TaskGet/Choice2.0 and2.1 over loopback; in-memory stores and synthetic provider finality. Test exchange maps fixed public path/query only. No __wire replay, public HTTP, provider, Claim, signing or purchase.'
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                result['server_exitcode'] = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill();proc.wait();raise AssertionError('Fixed server did not stop')
            result['stop_signal'] = 'SIGTERM'
            (out/'HTTP_RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
            assert result['server_exitcode'] == 0
    assert result['result'] == 'IMPLEMENTATION_SELF_CHECK_PASS'
    print(json.dumps(dict(result=result['result'],actual_taskget=len(calls),CLI_json=1,
                         checkout=COMMIT,version=result['version'],server_exitcode=result['server_exitcode'])))


if __name__ == '__main__':
    main()
