"""Test-only exchange of unchanged fixed wire with real SDK client/CLI."""
import base64
import contextlib
import io
import json
import sys
from unittest.mock import patch

from ln_church_agent import AgentTaskClient
from ln_church_agent.access_quota import AccessQuotaPolicy
from ln_church_agent.task_transport import TaskTransport


def query_for(case):
    if case['name'] == 'empty-range':
        raw = b'{"generation":"v1","after":"2099-01-01T00:00:00.000Z#task_z"}'
        return {'cursor': 'td1.' + base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}
    # Invalid query fixtures are separately tested before sending. Here their
    # unchanged error responses are deliberately injected into a valid query.
    q = case.get('query', {}) if case['status'] == 200 else {}
    return dict(limit=int(q.get('limit', '20')),
                **({'cursor': q['cursor']} if 'cursor' in q else {}))


class Replay:
    def __init__(self, case):
        self.case = case
        self.calls = []
        self.policy = AccessQuotaPolicy(wall_time=lambda: 1792222200)
        self.transport = TaskTransport(
            _resolver=lambda *_: ['8.8.8.8'], _exchange=self.send,
            _sleep=lambda _: (_ for _ in ()).throw(AssertionError('Unexpected retry')),
            access_quota=self.policy)
        self.client = AgentTaskClient(_transport=self.transport)

    def send(self, **kw):
        assert kw['method'] == 'GET' and kw['body'] is None
        assert kw['claim_token'] is None and not kw.get('access_headers')
        self.calls.append(dict(method=kw['method'], url=kw['url'], params=kw['params']))
        return self.case['status'], self.case.get('headers', {}), json.dumps(
            self.case.get('value', self.case.get('body')),
            ensure_ascii=False, separators=(',', ':')).encode()


def run_cli(client, kwargs=None, json_mode=False):
    from ln_church_agent.cli import main
    kwargs = kwargs or {}
    argv = ['ln-church-agent', 'task', 'discover']
    for name in ('limit', 'cursor'):
        if name in kwargs:
            argv += ['--' + name, str(kwargs[name])]
    if json_mode:
        argv += ['--json']
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch('ln_church_agent.task_client.AgentTaskClient', lambda: client), \
            patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        try:
            main()
        except SystemExit as e:
            code = e.code
    return dict(argv=argv, exitcode=code, stdout=out.getvalue(), stderr=err.getvalue())
