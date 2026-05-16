import argparse
from ln_church_agent import LnChurchClient

def main():
    parser = argparse.ArgumentParser(description="Auto-submit external observations to LN Church")
    parser.add_argument("--include-unmapped", action="store_true", help="Explicitly opt-in to submit unmapped/unknown discoveries (not payment proofs).")
    args = parser.parse_args()

    # Default conservative safe-list
    ELIGIBLE_CODES = ["x402_confirm_only", "post_settlement_proof_required"]
    
    # Test E & F: Explicit include_unmapped allows unmapped
    if args.include_unmapped:
        print("⚠️ Explicit Opt-In: Allowing submission of unmapped/unsupported discovery signals.")
        ELIGIBLE_CODES.extend([
            "payment_scheme_unmapped", 
            "unsupported_challenge_shape", 
            "unknown_rail", 
            "unsupported_rail"
        ])

    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    # Simulate an inspection loop result
    mock_inspection_results = [
        {"url": "https://api.example.com/data1", "code": "post_settlement_proof_required"},
        {"url": "https://api.example.com/data2", "code": "payment_scheme_unmapped"}
    ]

    for result in mock_inspection_results:
        code = result["code"]
        url = result["url"]

        if code in ELIGIBLE_CODES:
            if code in ["payment_scheme_unmapped", "unsupported_challenge_shape", "unknown_rail", "unsupported_rail"]:
                print(f"📡 Submitting unmapped discovery signal for {url}...")
                client.submit_unmapped_observation(
                    target_url=url,
                    detection_note=code,
                    rails_detected=["Payment"]
                )
            else:
                print(f"📡 Submitting standard observation for {url}...")
                client.submit_external_observation(
                    target_url=url,
                    evidence_class=code
                )
        else:
            print(f"⏭️ Skipping {url} (code '{code}' not in ELIGIBLE_CODES)")

if __name__ == "__main__":
    main()