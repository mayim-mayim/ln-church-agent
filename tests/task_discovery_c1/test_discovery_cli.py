"""CLI read-only discovery output, errors and existing list routing."""
import json
import sys
from unittest.mock import patch

import pytest

from discovery_fixtures import cursor,page
from test_discovery import Exchange
from ln_church_agent.access_quota import AccessQuotaError


def invoke(client,argv):
    from ln_church_agent.cli import main
    with patch('ln_church_agent.task_client.AgentTaskClient',lambda:client):
        with patch.object(sys,'argv',['ln-church-agent','task']+argv):
            main()


def test_cli_mixed_human_output_has_tuple_links_deadlines_and_next(capsys):
    wire=page((1,9,10,11),more=True);ex=Exchange(wire)
    invoke(ex.client,['discover','--limit','4'])
    out=capsys.readouterr()
    assert out.err==''
    for task in wire['tasks']:
        for key in ('task_id','task_type','task_definition_version','task_schema_version',
                    'task_definition_digest','detail_url','definition_url','claim_before'):
            assert task[key] in out.out
    assert wire['tasks'][0]['scheduled_at'] in out.out
    assert wire['next_cursor'] in out.out and 'eligibility' in out.out
    assert len(ex.calls)==1 and ex.calls[0]['params']=={'limit':4}


def test_cli_json_uses_only_public_new_page_allowlist(capsys):
    wire=page((10,11));wire['private_meta']='PRIVATE_BODY_MARKER'
    wire['tasks'][0]['answer']='PRIVATE_BODY_MARKER';ex=Exchange(wire)
    invoke(ex.client,['discover','--json'])
    captured=capsys.readouterr()
    payload=json.loads(captured.out)
    assert payload['schema_version']=='ln_church.task_discovery_page.v1'
    assert len(payload['tasks'])==2 and captured.err==''
    assert 'PRIVATE_BODY_MARKER' not in captured.out


def test_cli_empty_continuation_with_next_is_range_specific(capsys):
    wire=page((),continuation=True,more=True);ex=Exchange(wire)
    previous=cursor(after='2026-10-23T07:30:00.000Z#task_old')
    invoke(ex.client,['discover','--cursor',previous])
    out=capsys.readouterr().out
    assert 'continuation' in out and 'no_candidates_observed_in_range' in out
    assert wire['next_cursor'] in out and 'not a global inventory snapshot' in out


@pytest.mark.parametrize('status',[400,503,402])
def test_cli_http_failures_have_no_success_output(capsys,status):
    ex=Exchange({'message':'PRIVATE_BODY_MARKER'},status)
    with pytest.raises(SystemExit) as caught:invoke(ex.client,['discover','--json'])
    out=capsys.readouterr()
    assert caught.value.code==2 and out.out==''
    assert 'No candidate count was obtained' in out.err
    assert 'PRIVATE_BODY_MARKER' not in out.err


def test_cli_quota_errors_guide_wait_stop_or_authorized_purchase(capsys):
    class QuotaClient:
        def discover_tasks(self,**kw):raise AccessQuotaError('ACCESS_REQUIRED',origin_not_sent=True)
        def close(self):pass
    with pytest.raises(SystemExit):invoke(QuotaClient(),['discover'])
    out=capsys.readouterr()
    assert out.out==''
    assert all(text in out.err for text in ('access quota','authorized','wait','stop','does not buy'))
    assert 'No candidate count was obtained' in out.err


def test_cli_list_keeps_old_selector_and_json_shape(capsys):
    wire=dict(schema_version='ln_church.agent_task_page.v1',tasks=[],next_cursor=None)
    ex=Exchange(wire)
    invoke(ex.client,['list','--json'])
    out=capsys.readouterr()
    assert out.err=='' and json.loads(out.out)==wire
    assert ex.calls[0]['params']['task_type']=='payment_surface_discovery.v1'

