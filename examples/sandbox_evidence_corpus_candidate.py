import json
from ln_church_agent.evidence import build_sandbox_evidence_from_response, merge_sandbox_report_result, build_sandbox_corpus_candidate

def main():
    print("==================================================")
    print(" 🧪 Sandbox Evidence Corpus Candidate Generator")
    print("==================================================\n")

    # 1. Sandbox basic endpoint response (simulated)
    response_body = {
        "evidence_ref": {
            "schema_version": "sandbox_evidence_ref.v1",
            "evidence_scope": "sandbox_internal",
            "run_id": "run_999",
            "scenario_id": "mpp-charge-basic",
            "rail": "MPP",
            "payment_intent": "charge",
            "canonical_hash_expected": "hash123",
            "payment_receipt_present": True
        },
        "meta": {
            "interop_token": "RAW_SECRET_TOKEN_DO_NOT_STORE"
        },
        "canonical_hash": "hash123"
    }

    # 2. Build SandboxEvidence
    print("[1] Building SandboxEvidence from Response...")
    evidence = build_sandbox_evidence_from_response(response_body)

    # 3. Simulated Report Result merge
    print("[2] Merging Interop Report Results...")
    report_response = {
        "verification_status": "verified",
        "canonical_hash_matched": True,
        "server_payment_receipt_present": True,
        "client_reported_payment_receipt_present": True
    }
    merge_sandbox_report_result(evidence, report_response)

    # 4. Convert to Corpus Candidate
    print("[3] Evaluating Eligibility and converting to SandboxCorpusCandidate...")
    candidate = build_sandbox_corpus_candidate(evidence)

    # 5. Output
    print("\n✅ Sandbox Corpus Candidate Generated:")
    print("--------------------------------------------------")
    # Note: RAW_SECRET_TOKEN_DO_NOT_STORE is safely redacted and absent from candidate
    print(candidate.model_dump_json(indent=2))
    print("--------------------------------------------------")
    print(f"Eligible: {candidate.corpus_eligible}")
    print(f"Exclusion Reason: {candidate.exclusion_reason}")

    print("\n[Architecture Note]")
    print("- This candidate may be exported through a user-provided EvidenceRepository.")
    print("- The SDK does not submit this candidate to ExternalObserve or any remote corpus endpoint.")
    print("- Final corpus acceptance remains server-side.")

if __name__ == "__main__":
    main()