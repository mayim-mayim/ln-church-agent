"""Immediate v3 discovery and saved-v1/v2/v3 recovery; no work runs on import.

The new v3 pack must be received from DC before execution. Read the versioned Worker Guide
before a target GET. v2 uses the ExternalAgent role UA; v1 keeps its original UA.
This label proves no identity, and UA-dependent response changes affect matching.
"""
from ln_church_agent import AgentImmediateVisitClient, ImmediateVisitJournal


def discover(*, access_quota=None, version='v3', cursor=None):
    """Pass version='v1' for the legacy list; keep each version's cursor separate."""
    with AgentImmediateVisitClient(version=version, access_quota=access_quota) as client:
        return client.list_tasks(cursor=cursor)


def resume_saved_report(directory, *, task_id, execution_id, access_quota=None):
    """Use the credential's saved version and Report; never fetch the target again."""
    claim = ImmediateVisitJournal.load_claim(directory, task_id, execution_id)
    journal = ImmediateVisitJournal(directory, claim)
    report = journal.load_report(claim)
    if report is None:
        raise ValueError('No saved Report; this example does not retry a target fetch.')
    version = {'immediate_http_visit.v1': 'v1', 'immediate_http_visit.v2': 'v2', 'immediate_http_visit.v3': 'v3'}[claim.task_type]
    with AgentImmediateVisitClient(version=version, access_quota=access_quota) as client:
        return client.recover_completion(claim, report, journal=journal)


def prepare_requester_registration(client, *, plan_id, repeat_policy, urls):
    """Client default v3 or explicit v1; review the quote before payment signing."""
    return client.prepare_registration(plan_id=plan_id, repeat_policy=repeat_policy, urls=urls)


def recover_requester_registration(registration_client, *, saved_task_type, operation_ref, payer, read_signer):
    """Retain the original saved v1/v2/v3 type even when current default is v2."""
    challenge = registration_client.get_registration_challenge(saved_task_type, operation_ref, payer)
    proof = challenge.sign(read_signer)
    return proof, registration_client.read_registration(proof)
