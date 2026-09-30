"""Explicit Requester registration using the existing configured EVM signer.

Importing does not connect, sign or pay. Review public payment_terms and the
private input before calling authorize_payment. Preserve operation_ref before
submit_original; raw payment/input stays private, in caller-controlled memory.
"""
from ln_church_agent import OfferRegistrationClient


def prepare(client, registration_input):
    return client.prepare_registration(registration_input)


def authorize_payment(quote, existing_evm_signer):
    """Call only after the owner has authorized the displayed fee and input."""
    return quote.sign(existing_evm_signer)


def submit_original(client, operation):
    # Keep operation.operation_ref before dispatch, without logging its private data.
    return client.submit_registration(operation)


def begin_read_recovery(client, *, task_type, operation_ref, payer, read_signer):
    challenge = client.get_registration_challenge(task_type, operation_ref, payer)
    proof = challenge.sign(read_signer)  # Explicit read-only signing, not payment.
    return proof, client.read_registration(proof)


def continue_read_recovery(client, proof):
    """No wallet/signature callback is invoked. Expiry requires explicit renewal."""
    return client.read_registration(proof)


def refresh_read_recovery_explicitly(client, *, task_type, operation_ref, payer, read_signer):
    return begin_read_recovery(client, task_type=task_type, operation_ref=operation_ref,
                               payer=payer, read_signer=read_signer)
