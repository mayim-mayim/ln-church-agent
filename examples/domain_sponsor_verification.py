"""
Verified Domain Sponsor MVP v1 Flow
----------------------------------------------------
This script demonstrates how to securely issue a domain sponsor challenge,
save the document locally, and request verification after placing it on your domain.

Note: No private keys or payment payloads are required for this phase.
Proof headers verify that you were the original sponsor of the request.
"""
import os
import sys
from ln_church_agent import LnChurchClient

def main():
    request_id = os.environ.get("LN_CHURCH_REQUEST_ID")
    result_handle = os.environ.get("LN_CHURCH_RESULT_HANDLE")
    request_hash = os.environ.get("LN_CHURCH_REQUEST_HASH")

    if not request_id or not result_handle or not request_hash:
        print("❌ Error: Missing required environment variables:")
        print("  LN_CHURCH_REQUEST_ID, LN_CHURCH_RESULT_HANDLE, LN_CHURCH_REQUEST_HASH")
        print("  These are returned when you register a paid observation slot.")
        sys.exit(1)

    print("==================================================")
    print(" 🛡️ Verified Domain Sponsor Setup")
    print("==================================================\n")

    client = LnChurchClient(agent_id="domain_sponsor_cli")

    try:
        # [1] Issue Challenge
        print("[1] Requesting Sponsor Challenge...")
        challenge = client.create_domain_sponsor_challenge(
            request_id,
            result_handle=result_handle,
            request_hash=request_hash
        )
        print(f"  ✅ Challenge issued for {challenge.domain}")
        
        # [2] Save Document Safely
        file_path = ".well-known/ln-church-domain-sponsor.json"
        print(f"\n[2] Saving Challenge Document locally to {file_path} ...")
        client.save_domain_sponsor_challenge_document(challenge, file_path)
        print("  ✅ File saved.")
        
        # [3] Instructions
        print("\n==================================================")
        print(" 📤 PLACEMENT INSTRUCTIONS")
        print("==================================================")
        print("Please publish the generated JSON file to your domain exactly at:")
        print(f"  {challenge.challenge_url}")
        print("\nOnce the file is publicly accessible, you can verify it using:")
        print(f"  ln-church-agent observe-domain sponsor verify {request_id}")
        
        # Optionally, you can trigger verification programmatically:
        # verified = client.verify_domain_sponsor(request_id, result_handle=result_handle, request_hash=request_hash)
        
    except Exception as e:
        print(f"\n❌ Execution Failed: {str(e)}")

if __name__ == "__main__":
    main()