import os
import sys
from ln_church_agent import LnChurchClient

def main():
    agent_key = os.environ.get("AGENT_PRIVATE_KEY")
    domain = os.environ.get("DOMAIN", "example.com")
    idempotency_key = os.environ.get("IDEMPOTENCY_KEY")

    if not agent_key:
        print("❌ Error: AGENT_PRIVATE_KEY is missing. You need funds to register.")
        sys.exit(1)

    print("==================================================")
    print(" 🔭 Paid Domain Observation Slot Registration")
    print("==================================================\n")

    client = LnChurchClient(private_key=agent_key)
    
    print(f"📡 Registering observation slot for: {domain} ...")
    try:
        res = client.register_domain_observation_slot(
            domain=domain,
            idempotency_key=idempotency_key
        )
        print("✅ SUCCESS! Paid action accepted.\n")
        print(f"  Request ID    : {res.request_id}")
        print(f"  Status URL    : {res.status_url}")
        print(f"  Read Model    : {res.public_read_model_url}")
        print(f"  Result Handle : {res.result_handle}")
        print(f"  Request Hash  : {res.request_hash}")
        
    except Exception as e:
        print(f"❌ Failed to register slot: {e}")

if __name__ == "__main__":
    main()