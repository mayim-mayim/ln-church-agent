"""Fresh-process responder probe. stdout contains only hashes/counts/states."""
import hashlib
import json
import sys

from ln_church_agent import structured_response_contract as c
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_transport import StructuredResponseTransport
from ln_church_agent.task_journal import JournalError
from test_v1_18_14_b3_integration import LocalExchange


def bindings(journal):
    task_id, key, body, started = journal.claim_request()
    claim = journal.load_claim()
    report = journal.load_report()
    return dict(task_sha256=c.digest(task_id), claim_key_sha256=c.digest(key),
        claim_body_sha256=hashlib.sha256(body).hexdigest(), claim_started=started,
        claim_binding_sha256=c.digest(claim._private_payload()) if claim else None,
        report_sha256=report.report_sha256 if report else None)


def main():
    request = json.load(sys.stdin)
    exchange = LocalExchange(request['origin'])
    try:
        journal = StructuredResponseJournal.open(request['directory'], request['handle'])
        before = bindings(journal)
        client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=exchange))
        receipt_hash = None
        if request['action'] == 'recover_claim':
            claim = client.recover_claim(journal=journal)
            context = client.get_context(journal=journal)
            assert context.context_id == claim.context_id == journal.load_task().context_id
            state = 'claim_recovered'
        else:
            saved = journal.load_report().canonical_bytes
            state = client.recover_completion(journal=journal).state
            status = client.get_submission_status(journal=journal)
            context = client.get_context(journal=journal)
            assert status.report_sha256 == journal.load_report().report_sha256
            assert status.context_id == context.context_id == journal.load_claim().context_id
            assert saved == journal.load_report().canonical_bytes
            receipt_hash = c.digest({key:getattr(status,key) for key in
                ('task_id','execution_id','submission_id','report_sha256','received_at','evaluation_deadline')})
        return dict(state=state, before=before, after=bindings(journal),
            original_receipt_binding_sha256=receipt_hash,
            http_methods=[call['method'] for call in exchange.calls],
            recovery_read_headers=[call['recovery_read'] for call in exchange.calls],
            context_binding_preserved=True, sdk_import_path=c.__file__)
    except JournalError as error:
        return dict(state='recovery_required', code=error.code,
            http_methods=[call['method'] for call in exchange.calls])


if __name__ == '__main__':
    print(json.dumps(main()))
