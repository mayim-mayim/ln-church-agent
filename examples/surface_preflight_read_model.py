import os
from ln_church_agent import LnChurchClient

def main():
    print("==================================================")
    print(" 🔍 Surface Preflight Read Model Demo")
    print("==================================================\n")

    # Load from environment variable for identity anchor, though not strictly required for read-only
    agent_key = os.environ.get("AGENT_PRIVATE_KEY")
    if not agent_key:
        print("⚠️ Note: AGENT_PRIVATE_KEY not set. Using anonymous pipeline simulation.")
        agent_key = "0x0000000000000000000000000000000000000000000000000000000000000001"

    client = LnChurchClient(private_key=agent_key, base_url="https://kari.mayim-mayim.com")

    print("[1] Querying by target_url (Derived Key)...")
    try:
        card1 = client.get_surface_preflight(
            target_url="https://api.example.com/protected",
            method="GET",
            rail="x402",
            network="eip155:8453",
            asset="USDC",
            authorization_scheme="x402",
            draft_shape="exact"
        )
        print(f"  -> Schema: {card1.get('schema_version')}")
        print(f"  -> Known Surface: {card1.get('surface', {}).get('known')}")
        print(f"  -> Recommendation? : {not card1.get('not_a_recommendation')}")
        print(f"  -> Final Authority : {card1.get('guardrails', {}).get('final_authority')}")
        
        # Note on Compact Mode
        if "limitations" in card1 and any("compact mode" in l for l in card1["limitations"]):
            print("  -> (Note: This payload was served in compact mode. Rich settlement options are omitted.)")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")

    print("\n[2] Querying by surface_key directly...")
    try:
        # A mock/unknown surface key
        card2 = client.get_surface_preflight(surface_key="surface_0123456789abcdef01234567")
        is_known = card2.get('surface', {}).get('known')
        print(f"  -> Known Surface: {is_known}")
        if not is_known:
            print("  -> Unknown does not mean unsafe; it only means unobserved by the registry.")
    except Exception as e:
        print(f"  ❌ Error: {e}")

    print("\n[3] Notice: Execution Boundary")
    print("  -> No payment was executed.")
    print("  -> No telemetry was automatically submitted.")
    print("  -> The core `execute_detailed()` execution loop was bypassed entirely.")

if __name__ == "__main__":
    main()