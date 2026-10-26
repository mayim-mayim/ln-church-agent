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


def _call(operation, definition_version=None):
    try:
        options = {} if definition_version in (None, '3.0.0') else {'definition_version': definition_version}
        with StructuredResponseClient(**options) as client:
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
    def structured_response_list_tasks(limit:int=25,cursor:Optional[str]=None,definition_version:str='3.0.0')->Dict[str,Any]:
        """Read available structured response Tasks. Does not Claim or submit.

        For Structured 3.0.0/3.1.0, read the selected Task detail and
        https://kari.mayim-mayim.com/SKILL.md#structured-claim-guidance before
        an explicit Claim. Tuple support does not establish personal eligibility.
        """
        return _call(lambda c:c.list_tasks(limit=limit,cursor=cursor),definition_version)

    @mcp.tool()
    def structured_response_get_task(task_id:str,definition_version:str='3.0.0')->Dict[str,Any]:
        """Read question, types, quality, reward, participation and visibility.

        For Structured 3.0.0/3.1.0, review this Task's concrete conditions and
        https://kari.mayim-mayim.com/SKILL.md#structured-claim-guidance before
        an explicit Claim. supported/read_only/update_required indicate tuple
        support, not personal eligibility; the Agent must review the detail.
        """
        def read(c):
            t=c.get_task(task_id)
            return dict(task=t.model_dump(),read_only=not t.supported,update_required=t.update_required)
        return _call(read,definition_version)

    @mcp.tool()
    def structured_response_claim(task_id:str,agent_id:str,reward_address:str,idempotency_key:str,definition_version:str='3.0.0')->Dict[str,Any]:
        """Explicitly Claim once, saving the original key/request before dispatch. No wallet signature.

        For Structured 3.0.0/3.1.0, first review the selected Task detail,
        retained acceptance history for the same reward address, and
        https://kari.mayim-mayim.com/SKILL.md#structured-claim-guidance.
        Tuple support is not eligibility; insufficient information remains
        unconfirmed without adding a local proof gate. The Backend decides.
        """
        return _call(lambda c:c.claim(task_id,agent_id,reward_address,idempotency_key,journal_directory=_directory()),definition_version)

    @mcp.tool()
    def structured_response_recover_claim(journal_handle:str)->Dict[str,Any]:
        """Read the saved Claim binding. A miss never makes a new Claim.

        For Structured 3.0.0/3.1.0, consult the selected Task detail and
        https://kari.mayim-mayim.com/SKILL.md#structured-claim-guidance for
        state-specific recovery, including a known successful Claim. Keep the
        original Task, request and key. This tool does not expose or execute
        the new recovery actions returned by the Backend.
        """
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
