"""Explicit responder MCP; preserves the existing inspect-only MCP surface."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional,List,Dict,Any

from ..structured_response_client import StructuredResponseClient
from ..structured_response_journal import StructuredResponseJournal
from ..structured_response_transport import StructuredResponseError,StructuredResponseAPIError
from ..access_quota import AccessQuotaError
from ..task_journal import JournalError
from .._structured_response_crypto import RECOVERY_ACTIONS


def _directory():
    configured=os.environ.get('LN_CHURCH_TASK_JOURNAL_DIR')
    if configured:
        root=Path(configured)
    elif os.name=='nt':
        root=Path(os.environ['LOCALAPPDATA'])/'ln-church-agent'/'claims'
    else:
        root=Path.home()/'.local'/'share'/'ln-church-agent'/'claims'
    root.mkdir(parents=True,mode=0o700,exist_ok=True)
    return root


def _journal(handle):
    return StructuredResponseJournal.open(_directory(),handle)


def _call(operation):
    try:
        with StructuredResponseClient() as client:
            value=operation(client)
            return value.model_dump() if hasattr(value,'model_dump') else value
    except StructuredResponseAPIError as e:
        return dict(state='unconfirmed',code=e.public_error_code,status_code=e.status_code)
    except StructuredResponseError as e:
        return dict(state='unconfirmed',code=e.code,update_required=e.code=='UNSUPPORTED_TUPLE',journal_handle=e.journal_handle)
    except JournalError as e:
        if e.code in RECOVERY_ACTIONS:
            return dict(state='recovery_required',code=e.code,recoverable=True,
                recovery_action=RECOVERY_ACTIONS[e.code])
        return dict(state='unconfirmed',code=e.code)
    except AccessQuotaError:
        return dict(state='unconfirmed',code='ACCESS_QUOTA_UNCONFIRMED')
    except Exception:
        return dict(state='unconfirmed',code='INVALID_STRUCTURED_RESPONSE_OPERATION')


def register_tools(mcp):
    @mcp.tool()
    def structured_response_list_tasks(limit:int=25,cursor:Optional[str]=None)->Dict[str,Any]:
        """Read available structured response Tasks. Does not Claim or submit."""
        return _call(lambda c:c.list_tasks(limit=limit,cursor=cursor))

    @mcp.tool()
    def structured_response_get_task(task_id:str)->Dict[str,Any]:
        """Read question, types, quality, reward, participation and visibility."""
        def read(c):
            t=c.get_task(task_id)
            return dict(task=t.model_dump(),read_only=not t.supported,update_required=t.update_required)
        return _call(read)

    @mcp.tool()
    def structured_response_claim(task_id:str,agent_id:str,reward_address:str,idempotency_key:str)->Dict[str,Any]:
        """Explicitly Claim once, saving the original key/request before dispatch. No wallet signature."""
        return _call(lambda c:c.claim(task_id,agent_id,reward_address,idempotency_key,journal_directory=_directory()))

    @mcp.tool()
    def structured_response_recover_claim(journal_handle:str)->Dict[str,Any]:
        """Read the saved Claim binding. A miss never makes a new Claim."""
        return _call(lambda c:c.recover_claim(journal=_journal(journal_handle)))

    @mcp.tool()
    def structured_response_get_context(journal_handle:str)->Dict[str,Any]:
        """Read fixed context and permitted source projections using the saved credential."""
        return _call(lambda c:c.get_context(journal=_journal(journal_handle)))

    @mcp.tool()
    def structured_response_prepare_answer(journal_handle:str,shared_assumptions:Dict[str,str],items:List[Dict[str,Any]],submission_id:Optional[str]=None,correction:bool=False)->Dict[str,Any]:
        """Locally validate and save canonical answers; sends nothing. Correction requires a definite unaccepted structural rejection and a new ID."""
        def prepare(c):
            r=c.prepare_answer(journal=_journal(journal_handle),shared_assumptions=shared_assumptions,
                items=items,submission_id=submission_id,correction=correction)
            return dict(state='prepared',journal_handle=journal_handle,submission_id=r.report['submission_id'],report_sha256=r.report_sha256)
        return _call(prepare)

    @mcp.tool()
    def structured_response_submit(journal_handle:str)->Dict[str,Any]:
        """Explicitly send saved bytes with the same submission ID; finite recovery."""
        return _call(lambda c:c.submit(journal=_journal(journal_handle)))

    @mcp.tool()
    def structured_response_get_submission_status(journal_handle:str)->Dict[str,Any]:
        """Read acceptance, quality, content, entitlement and payout separately, including after Claim expiry."""
        return _call(lambda c:c.get_submission_status(journal=_journal(journal_handle)))

    @mcp.tool()
    def structured_response_recover_completion(journal_handle:str)->Dict[str,Any]:
        """Read status first, then only the same saved bytes/ID if still unconfirmed; no new submission."""
        return _call(lambda c:c.recover_completion(journal=_journal(journal_handle)))

    @mcp.tool()
    def structured_response_abandon(journal_handle:str,idempotency_key:str)->Dict[str,Any]:
        """Explicitly release an unaccepted Claim. Accepted or outcome-unknown work cannot be cancelled."""
        return _call(lambda c:c.abandon(journal=_journal(journal_handle),idempotency_key=idempotency_key))


def main():
    from mcp.server.fastmcp import FastMCP
    mcp=FastMCP('LN_Church_Task_Responder')
    register_tools(mcp)
    mcp.run()


if __name__=='__main__':
    main()
