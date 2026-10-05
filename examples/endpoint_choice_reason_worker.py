"""Explicit Python calls for Choice v2, with saved v1 recovery.

The new pack must be received from DC before v2 execution. Importing this file performs no
network operation. The caller supplies a private directory and retains the same
Task, agent, reward address and high-entropy Claim key across restarts. No payment
signer is needed for free access; keep any explicitly approved AccessQuotaPolicy
alive while an access purchase is unresolved. The journal does not persist it.
Read docs/endpoint-choice-reason.md before answering: the reason becomes public
after intake closes and is sent through Cloudflare/TypeSafe for evaluation.
"""
from ln_church_agent import EndpointChoiceJournal


def open_claim_journal(directory, *, task_id, agent_id, reward_address, claim_key, version="v2"):
    """The directory must already exist with private permissions (0700 on Linux)."""
    return EndpointChoiceJournal(directory, task_id=task_id, agent_id=agent_id,
                                 reward_address=reward_address, idempotency_key=claim_key, version=version)


def claim(client, journal):
    """Use the same call and live policy to continue an explicit access purchase.

    After restart, this reopens the saved Claim through the read-only recovery
    route. A missing binding is not permission to create a new Claim.
    """
    return client.claim_task(journal=journal)


def prepare_and_submit(client, journal, *, selected_candidate_id, answer_reason):
    """Caller chooses the candidate/reason; no fetching, translation or generation.

    Call once for a new answer. On uncertain delivery use resume_answer instead.
    This function does not correct or replace an existing saved answer.
    """
    if journal.load_report() is not None:
        raise ValueError('A saved answer exists; use resume_answer with this journal.')
    client.prepare_answer(journal=journal, selected_candidate_id=selected_candidate_id,
                          answer_reason=answer_reason)
    return client.complete_task(journal=journal)


def resume_answer(client, journal):
    """Status-first; only the original saved ID/body may be replayed."""
    return client.recover_completion(journal=journal)


def evaluation_snapshot(client, journal):
    """Return server-owned non-secret evaluation facts, never the raw private row."""
    result = client.get_submission_status(journal=journal)
    return {'evaluation': result.evaluation.model_dump(),
            'payout': result.payout.model_dump()}
