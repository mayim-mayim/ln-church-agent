"""Explicit versioned Paid client use; no I/O or signing runs on import.

Unreleased 1.18.11 v3 support includes the DC-fixed producer pack. Purchase cost may exceed
0.02 USDC reward; existing PaymentPolicy limits/permissions still apply.
"""
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.paid_service_trial_contract import version_of


def discover(*, version='v3', access_quota=None, cursor=None):
    with PaidServiceTrialTaskClient(version=version, access_quota=access_quota) as client:
        return client.list_tasks(cursor=cursor)


def resume_saved_report(directory, *, task_id, execution_id, access_quota=None):
    """Read the saved purchase/report; never create or sign another purchase."""
    claim=PaidServiceTrialJournal.load_claim(directory,task_id,execution_id)
    journal=PaidServiceTrialJournal(directory,claim)
    report=journal.load_report()
    if report is None:
        raise ValueError('No saved Report; this example does not initiate a purchase.')
    with PaidServiceTrialTaskClient(version=version_of(claim),claim_directory=directory,access_quota=access_quota) as client:
        return client.recover_completion(claim,report,journal=journal)
