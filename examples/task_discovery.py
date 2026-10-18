"""One explicit read-only discovery call; no I/O runs on import.

Discovery c1 / SDK 1.18.15 candidate. Requires the new server page schema.
Read each candidate's official detail and Guide before selecting its dedicated
client. No Claim, target visit, signing, purchase or automatic page loop here.
"""

from ln_church_agent import AgentTaskClient


def discover_one_page(*, limit=20, cursor=None):
    """Supply a saved discovery cursor only to explicitly continue its range."""
    with AgentTaskClient() as client:
        return client.discover_tasks(limit=limit, cursor=cursor)


def main():
    page = discover_one_page()
    print("Scope:", page.page_scope, "checked:", page.checked_at)
    print("Empty reason:", page.empty_reason)
    for candidate in page.tasks:
        print(candidate.task_id, candidate.task_type,
              candidate.task_schema_version, candidate.task_definition_version,
              candidate.task_definition_digest, candidate.capacity_available)
        print("Detail:", candidate.detail_url)
        print("Guide:", candidate.definition_url)
    print("Next cursor:", page.next_cursor)
    # An explicit later choice can call discover_one_page(cursor=page.next_cursor)
    # when it is non-null. Do not mix with a dedicated client's list cursor.
    # For a fresh search after changes, call discover_one_page() without cursor.
    # AccessQuotaError / TaskError propagates: never turn a failed read into [].
    # The default policy does not purchase quota. Explicit policy authorization,
    # waiting for reset, and stopping remain separate caller decisions.


if __name__ == "__main__":
    main()
