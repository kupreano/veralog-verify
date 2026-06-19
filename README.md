# Veralog Standalone Verifier

**Verify AI audit trails WITHOUT a Veralog account.**

No API key required. No internet required. MIT License.

```bash
pip install cryptography
python standalone_verifier.py --export your_audit_export.json
```

## What it verifies

1. **Ed25519 signatures** — every event was signed by Veralog's key
2. **SHA-256 hash chain** — no events were deleted or reordered
3. **Coverage gaps** — sequence numbers are continuous

## Quick start

```bash
# 1. Get Veralog's public key (no account needed)
curl https://www.vrlg.tech/key-transparency > key_transparency.json

# 2. Export your audit data (requires your API key)
curl -H "x-api-key: vrlg_..." https://www.vrlg.tech/export > audit.json

# 3. Verify — no internet needed after this point
python standalone_verifier.py --export audit.json

# Expected output:
# ✅ 1,247 signatures valid
# ✅ Hash chain intact — 0 gaps
# ✅ All records authentic and unmodified
```

## Why this exists

You should never have to trust Veralog.

The cryptographic proof is in your data. This verifier
lets you — or your auditor — confirm integrity independently.

## For auditors

```bash
# Verify a single event
python standalone_verifier.py \
  --event event.json \
  --pubkey 501c4abadd22e01a...

# Get Veralog's public key out-of-band
curl https://www.vrlg.tech/key-transparency
# Cross-check: https://github.com/kupreano/veralog-verify/blob/main/PUBLIC_KEY.txt
```

## License

MIT — use freely in any environment, including air-gapped.
