#!/usr/bin/env python3
"""
Veralog Standalone Verifier v1.0
MIT License — use freely, no Veralog account required.

Verifies Veralog audit trail WITHOUT Veralog API.
Requires only: cryptography library + exported data.

Usage:
    pip install cryptography
    python standalone_verifier.py --export audit_export.json
    python standalone_verifier.py --event event.json --pubkey public_key.hex
    python standalone_verifier.py --help
"""

import argparse
import json
import sys
import hashlib
import binascii

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("❌ Missing dependency: pip install cryptography")
    sys.exit(1)


VERSION = "1.0.0"
VERALOG_KEY_TRANSPARENCY_URL = "https://www.vrlg.tech/key-transparency"


def verify_signature(event: dict, public_key_hex: str) -> dict:
    """
    Verify Ed25519 signature on a single event.
    Returns: {valid: bool, message: str}
    """
    try:
        pk_bytes = binascii.unhexlify(public_key_hex)
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)

        msg = (
            f"{event['event_id']}:{event['agent_id']}"
            f":{event['action']}:{event['timestamp']}"
        ).encode()

        pk.verify(binascii.unhexlify(event["signature"]), msg)
        return {"valid": True, "message": "✅ Signature valid"}
    except InvalidSignature:
        return {"valid": False, "message": "❌ INVALID SIGNATURE — event may be tampered"}
    except Exception as e:
        return {"valid": False, "message": f"❌ Error: {e}"}


def verify_event_hash(event: dict) -> dict:
    """Verify SHA-256 event hash."""
    try:
        sig = event.get("signature", "")
        prev_hash = event.get("previous_hash", "0" * 64)
        seq = event.get("sequence_number", 0)

        computed = hashlib.sha256(
            f"{event['event_id']}:{event['agent_id']}:{event['action']}"
            f":{event['timestamp']}:{sig}:{prev_hash}:{seq}".encode()
        ).hexdigest()

        stored = event.get("event_hash", "")
        if computed == stored:
            return {"valid": True, "message": "✅ Hash valid"}
        else:
            return {
                "valid": False,
                "message": f"❌ HASH MISMATCH — computed: {computed[:16]}... stored: {stored[:16]}..."
            }
    except Exception as e:
        return {"valid": False, "message": f"❌ Error: {e}"}


def verify_chain(events: list) -> dict:
    """Verify hash chain continuity (no gaps, no reordering)."""
    sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))

    gaps = []
    prev_hash_violations = []
    prev_hash = "0" * 64
    prev_seq = 0

    for e in sorted_events:
        seq = e.get("sequence_number", 0)
        e_prev_hash = e.get("previous_hash", "")

        # Check sequence gap
        if prev_seq > 0 and seq != prev_seq + 1:
            gaps.append({"missing_after_seq": prev_seq, "next_seq": seq})

        # Check hash linkage
        if prev_seq > 0 and e_prev_hash != prev_hash:
            prev_hash_violations.append({
                "seq": seq,
                "expected": prev_hash[:16] + "...",
                "found":    e_prev_hash[:16] + "..."
            })

        prev_hash = e.get("event_hash", "")
        prev_seq = seq

    return {
        "valid":               len(gaps) == 0 and len(prev_hash_violations) == 0,
        "total_events":        len(sorted_events),
        "gaps_found":          len(gaps),
        "hash_violations":     len(prev_hash_violations),
        "gaps":                gaps[:5],
        "hash_violations_detail": prev_hash_violations[:5],
        "message": "✅ Chain intact" if len(gaps) == 0 else f"❌ {len(gaps)} gaps found",
    }


def verify_export(export_file: str, verbose: bool = False) -> None:
    """Verify a full export from forensic.py evidence-pack."""
    print(f"\n{'='*60}")
    print(f"VERALOG STANDALONE VERIFIER v{VERSION}")
    print(f"{'='*60}\n")

    with open(export_file, "r", encoding="utf-8") as f:
        export = json.load(f)

    events = export.get("events", [])
    print(f"Export: {export_file}")
    print(f"Events: {len(events)}")
    print(f"Period: {export.get('period_start', 'unknown')[:10]} → {export.get('exported_at', '')[:10]}\n")

    if not events:
        print("❌ No events to verify")
        return

    # Get public key from first event
    public_key_hex = events[0].get("public_key", "")
    if not public_key_hex:
        print("❌ No public key found in events")
        return

    print(f"Public key: {public_key_hex[:16]}...{public_key_hex[-8:]}")
    print(f"Tip: Verify this key at {VERALOG_KEY_TRANSPARENCY_URL}\n")

    # Verify signatures
    print("1. VERIFYING Ed25519 SIGNATURES...")
    valid_sigs = 0
    invalid_sigs = []
    for e in events:
        result = verify_signature(e, public_key_hex)
        if result["valid"]:
            valid_sigs += 1
        else:
            invalid_sigs.append({"event_id": e.get("event_id"), "error": result["message"]})
            if verbose:
                print(f"   {result['message']} — {e.get('event_id', '')[:8]}")

    sig_pct = round(valid_sigs / len(events) * 100, 1)
    print(f"   {'✅' if not invalid_sigs else '❌'} {valid_sigs}/{len(events)} valid ({sig_pct}%)")
    if invalid_sigs[:3]:
        for inv in invalid_sigs[:3]:
            print(f"   ❌ {inv['event_id'][:8]}: {inv['error']}")

    # Verify hashes
    print("\n2. VERIFYING SHA-256 EVENT HASHES...")
    valid_hashes = 0
    invalid_hashes = []
    for e in events:
        result = verify_event_hash(e)
        if result["valid"]:
            valid_hashes += 1
        else:
            invalid_hashes.append(e.get("event_id"))

    hash_pct = round(valid_hashes / len(events) * 100, 1)
    print(f"   {'✅' if not invalid_hashes else '❌'} {valid_hashes}/{len(events)} valid ({hash_pct}%)")

    # Verify chain
    print("\n3. VERIFYING HASH CHAIN CONTINUITY...")
    chain_result = verify_chain(events)
    print(f"   {chain_result['message']}")
    if chain_result["gaps"]:
        for g in chain_result["gaps"]:
            print(f"   ❌ Gap after seq {g['missing_after_seq']} (next: {g['next_seq']})")

    # Summary
    all_valid = (not invalid_sigs) and (not invalid_hashes) and chain_result["valid"]
    print(f"\n{'='*60}")
    print(f"RESULT: {'✅ ALL VERIFIED — data is authentic and unmodified' if all_valid else '❌ VERIFICATION FAILED — investigate above errors'}")
    print(f"{'='*60}")
    print(f"\nThis verification ran without Veralog API.")
    print(f"It uses only: Ed25519 public key + SHA-256 + sequence numbers.")
    print(f"Source: https://github.com/kupreano/veralog-api (MIT License)")


def verify_single_event(event_file: str, pubkey_hex: str) -> None:
    """Verify a single event JSON file."""
    with open(event_file, "r") as f:
        event = json.load(f)

    print(f"\nVerifying event: {event.get('event_id', '')[:16]}...")

    sig_result  = verify_signature(event, pubkey_hex)
    hash_result = verify_event_hash(event)

    print(f"Signature:  {sig_result['message']}")
    print(f"Hash:       {hash_result['message']}")
    print(f"Agent:      {event.get('agent_id')}")
    print(f"Action:     {event.get('action')}")
    print(f"Timestamp:  {event.get('timestamp')}")
    print(f"PTA flags:  {event.get('pta_flags', [])}")


def main():
    parser = argparse.ArgumentParser(
        description=f"Veralog Standalone Verifier v{VERSION} — verify audit trail without Veralog API"
    )
    parser.add_argument("--export",   help="Path to evidence-pack audit.json export")
    parser.add_argument("--event",    help="Path to single event JSON")
    parser.add_argument("--pubkey",   help="Veralog public key hex (for single event verification)")
    parser.add_argument("--verbose",  action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.export:
        verify_export(args.export, verbose=args.verbose)
    elif args.event and args.pubkey:
        verify_single_event(args.event, args.pubkey)
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python standalone_verifier.py --export audit.json")
        print("  python standalone_verifier.py --event event.json --pubkey 501c4aba...")
        print(f"\nGet Veralog public key: curl {VERALOG_KEY_TRANSPARENCY_URL}")


if __name__ == "__main__":
    main()
