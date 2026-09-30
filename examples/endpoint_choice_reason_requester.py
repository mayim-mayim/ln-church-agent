"""Explicit, memory-only Requester reads for SDK 1.18.9.

These examples neither register nor purchase an Offer. For registration and original-payment recovery see endpoint_choice_reason_registration.py.
The signer is supplied by the caller, after an explicit read-proof decision.
Do not log the signer input, proof, registration data or private answer rows.
"""


def begin_results(client, *, task_id, payer, signer, limit=20, cursor=None):
    """Explicitly sign once, then keep the proof in page memory."""
    challenge = client.get_results_challenge(task_id, payer)
    proof = challenge.sign(signer)
    return proof, client.read_results(proof, limit=limit, cursor=cursor)


def read_next_page(client, proof, *, cursor, limit=20):
    """Reuses the proof; no automatic refresh, signing or payment."""
    return client.read_results(proof, limit=limit, cursor=cursor)


def refresh_results_explicitly(client, *, task_id, payer, signer, cursor, limit=20):
    """Caller explicitly requests refresh, retaining the Task and page position."""
    return begin_results(client, task_id=task_id, payer=payer, signer=signer,
                         limit=limit, cursor=cursor)
