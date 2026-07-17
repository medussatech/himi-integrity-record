<!--
  HIMI verification README — complete draft.
  All 10 sections confirmed against real code:
    - hash recipe (§4) against ledger.py's compute_result_hash
    - file formats, Merkle root, digest chain (§3/§5/§6) against digest_daily.py
    - OTS commands (§10) tested against OpenTimestamps client 0.7.2 on VPS1
  No PENDING blocks remain. Ready to place in the repo at genesis.
  Still to add later by commit (additive, non-blocking): Zenodo DOI (§9),
  VPS2 latency artifact chapter.
-->

# HIMI — Cross-Domain Integrity Record

A public, append-only, verifiable record of a live cross-domain classification
experiment. **Status: the experiment is running. We are not selling conclusions —
we are publishing a record you can check.**

---

## 1. What this repository is

This repository is the public integrity record of the HIMI cross-domain validation
experiment. Each entry is a deterministic classification produced by the HIMI engine
over open sensor data (NOAA NDBC marine telemetry, ENTSO-E European grid load,
NASA GISS GISTEMP). Every entry carries a per-entry SHA-256 digest (`result_hash`)
computed from a canonical payload, and the complete set of entries is committed to a
Merkle root that is anchored to the Bitcoin blockchain via OpenTimestamps.

The purpose of this repository is to let anyone verify the **integrity of the record** —
that entries have not been altered, reordered, or backdated — independently of us and
without trusting us.

## 2. What this is — and what this is NOT

**This lets you verify** the integrity of the record: which entries exist, in what order,
and with what content.

**This does NOT (yet) claim** that HIMI's classifications are correct or valuable. That is
a separate, open question, to be judged in public and after the fact. Method transparency
comes first; validity of results comes later, in the open. If you came here expecting a
proof that the method "works", this is not that document — this is the document that lets
you trust the record while that question stays open.

## 3. File formats

**`public_hashes.jsonl`** — the *leaves / input*. One JSON object per line:
`{"result_hash": "<64-hex>"}`. Derived by `emit_public_hashes.py` from the internal
ledger (`/opt/himi/data/gr7_track_record.json`) in **physical write order** over the
**full ledger** — not the 500-entry-per-node recent window. This is the file that is
published and anchored, so *what is sealed is exactly what you download*.

**`digest_ledger.jsonl`** — the *roots / chain*. One digest record per line, serialized
canonically (`sort_keys=True`, no spaces). Each record has exactly these fields:

| Field | Type | Meaning |
|-------|------|---------|
| `computed_at` | string | UTC timestamp, `YYYY-MM-DDTHH:MM:SSZ` |
| `entry_count` | int | cumulative number of public entries covered |
| `merkle_root` | hex | RFC 6962 root over the leaves, in order (see §5) |
| `prev_digest_hash` | hex or `null` | previous line's `digest_hash`; `null` on the genesis line |
| `leaf_source` | string | `"per_entry_result_hash"` |
| `merkle_spec` | string | `"rfc6962-sha256"` |
| `digest_hash` | hex | SHA-256 of this record's canonical form, *excluding* `digest_hash` itself (see §6) |

## 4. How to verify a single entry's hash

Each entry's `result_hash` is a SHA-256 over a **canonical payload of exactly 4 fields**:
`input_hash`, `state`, `ignition_probability`, `metabolic_health`. The two floats are
rounded to **8 decimals** (for cross-platform determinism — floating-point noise across
CPU/BLAS), the object is serialized with `sort_keys=True` (so field order is alphabetical
by construction), UTF-8 encoded, and hashed:

```python
import json, hashlib

def compute_result_hash(input_hash, state, ignition_probability, metabolic_health):
    canonical = {
        "input_hash": input_hash,
        "state": state,
        "ignition_probability": round(ignition_probability, 8),
        "metabolic_health": round(metabolic_health, 8),
    }
    payload = json.dumps(canonical, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
```

To check any entry: take its four fields from the ledger, run them through the function
above, and confirm the output matches the stored `result_hash`, byte for byte.

## 5. How the official Merkle root is built

The root is an **RFC 6962** (Certificate Transparency) Merkle Tree Hash over the ordered
list of leaves. Exactly as implemented:

- `MTH([])`      = `SHA-256("")`
- `MTH([d0])`    = `SHA-256(0x00 || d0)`
- `MTH(D, n>1)`  = `SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`, with
  **k = the largest power of two strictly less than n**.

The `0x00` (leaf) / `0x01` (node) prefixes are RFC 6962 domain separation — they prevent
second-preimage attacks between tree levels.

**Two details an auditor must get right, or reproduction fails:**

1. **Leaf order** = the physical order of `public_hashes.jsonl` (= physical write order of
   the internal ledger). Do not sort or deduplicate.
2. **Leaf bytes** = the `result_hash` **hex string, UTF-8 encoded** — the ASCII bytes of
   the 64 hex characters, *not* the 32 raw bytes obtained by decoding the hex. This is
   deliberate: what is sealed is exactly the text you download.

To reproduce the root from `public_hashes.jsonl`: take each `result_hash` in order →
UTF-8 encode the hex string → apply the MTH above → the result must equal the
`merkle_root` field in `digest_ledger.jsonl` (and its anchored copy). No vectors are
needed to reconstruct the root.

## 6. The digest chain, and how to verify it

Each line's `digest_hash` is the SHA-256 of the record's **canonical serialization**
(`json.dumps(record, sort_keys=True, separators=(",", ":"))`, UTF-8) computed over the
record **with the `digest_hash` field removed**, then stored back into the same line.

The chain: every record's `prev_digest_hash` equals the previous record's `digest_hash`.
The **genesis** line has `prev_digest_hash: null`. Any edit to a past line breaks both its
own `digest_hash` and every subsequent `prev_digest_hash` link — that is what makes
retroactive tampering detectable.

You can verify the whole chain locally, without trusting us:

```bash
python3 digest_daily.py --verify --out digest_ledger.jsonl
```

It recomputes each `digest_hash`, checks it against the stored value, and checks each
`prev_digest_hash` link. The script also carries a self-contained proof of the Merkle
logic (hand-computed n=2 case plus a tampering-detection test):

```bash
python3 digest_daily.py --selftest
```

Note: `digest_daily.py` does **no** network. Publishing to GitHub and sealing with
OpenTimestamps are separate wrapper/timer steps (see §10).

## 7. Two roots — do not conflate them

The record exposes **two distinct roots**, deliberately labeled so no auditor mixes them:

- **The official root** — the OTS-sealed Merkle root covering the **full ledger**. This is
  the one anchored to Bitcoin and the only one that carries the integrity guarantee. It
  lives in `digest_ledger.jsonl` in *this* repository (the `merkle_root` field).
- **`merkle_root_recent`** — an **informational** root over a rolling window (the most
  recent 500 entries per node). It is computed by the browser-side dashboard for quick
  spot-checks and **lives in the dashboard, not in this repository** — you will not find
  it among the files here, and that is expected. It is **not** sealed and carries **no**
  anchoring guarantee.

If a claim about tamper-evidence is being made, it refers to the official root only.

## 8. What the anchor proves — and what it does NOT

The OpenTimestamps anchor attests the **set, the order, and the content** of the entries
(via their `result_hash` values), and it inherits whatever the canonical 4-field payload
covers (see §4). Concretely: it proves the record existed in this exact form no later than
the anchored time, and cannot be silently rewritten afterward.

It does **NOT** prove that the underlying source data is "true", and it says nothing about
anything inside the intra-day window **before** the external anchor lands.

## 9. Methodology (brief) → Zenodo

Data is pulled by domain-specific fetchers (NOAA NDBC, ENTSO-E, NASA GISTEMP) under
strict ingest rules: **resolve-once**, **first-write-wins**, **no imputation**, **no
backfill**. This README documents *how to verify the record*, not the full method. The
complete, reproducible methodology — engine design, normalization, the five-state
consensus — lives in the Zenodo publication (DOI to be added here by commit).

## 10. How to check the Bitcoin anchor

The sealing target is settled: OpenTimestamps seals **`digest_ledger.jsonl`** (which carries
the `merkle_root` and the chain), and **`public_hashes.jsonl`** is published alongside so
anyone can recompute the root (§5) and confirm it matches the sealed value. Tampering with
the leaves is caught because the recomputed root no longer matches the anchored one — so the
leaves inherit the anchor without needing their own.

**Sealing (done once per digest, by us, as a wrapper step — not inside any script):**

```bash
ots stamp digest_ledger.jsonl
```

This submits the file's hash to several public calendar servers and writes the receipt
`digest_ledger.jsonl.ots` next to it. Both files are committed to the repository.

**Verifying (anyone, at any time):**

```bash
ots verify digest_ledger.jsonl.ots
```

Immediately after sealing, each calendar reports `Pending confirmation in Bitcoin
blockchain` — the timestamp has been submitted but not yet included in a block. This is
expected, not an error; Bitcoin confirmation takes on the order of hours.

**Upgrading the receipt (once a block confirms it):**

```bash
ots upgrade digest_ledger.jsonl.ots
```

This fetches the completed proof from the calendars and rewrites `.ots` so it verifies
independently against the Bitcoin blockchain, with no further trust in the calendar servers.
We run `ots upgrade` periodically (weekly) and re-commit the upgraded `.ots`. After a
successful upgrade, `ots verify` prints the Bitcoin block height and timestamp the file was
anchored to — that timestamp is the trustless proof that the record existed, in exactly this
form, no later than that block.

---

*Every technical claim in this document is reproducible from the published files and the
code in this repository. If something here does not match what you can recompute yourself,
that mismatch is provable by anyone — you do not need us to confirm it, or even to reach us.
That is the point: the integrity of this record does not depend on trusting, or contacting,
its authors. Check it yourself; the files are all here.*

## 11. Input vectors — verifying the data → input_hash link

Sections 4–10 prove the chain `result_hash` → Merkle root → Bitcoin. That
chain does **not** need the input vectors — see §5. This section adds a
*separate, optional* layer: raw input vectors are published so the link
**raw data → `input_hash`** is also reproducible, not just committed.

Two files per published vector:

- `<name>.json` — the 600-point window, one `[timestamp, value]` pair per
  point, plus metadata (node, first_ts, last_ts, capture time, note).
- `<name>.json.ots` — an OpenTimestamps proof of that file (verify as in §10).

**How to verify a vector against the ledger.** The engine's `input_hash`
(stored as `vector_hash_sha256` in the experiment ledger) is computed over the
list of values alone — not the `[ts, value]` pairs:

    python3 -c "import json,hashlib; \
    d=json.load(open('nasa_vector_2026-07-16.json')); \
    vals=[p[1] for p in d['series']]; \
    print(hashlib.sha256(json.dumps(vals).encode('utf-8')).hexdigest())"

This must equal the `vector_hash_sha256` recorded for that classification
(for the file above: `76d6d4c4af7763fa224d9ef896a0fe465c32ceabf8bb2a64b516cf0c928927a0`).

The serialization is Python's `json.dumps` defaults: separators `", "` / `": "`,
integral floats printed as `1.0`, values in stored order. A JSON reproducer
must match these byte-for-byte.

**Coverage — read this before assuming symmetry across domains.** Publishing an
input vector requires that the exact 600-point window still exists. This is not
equally true for all domains:

- **NASA** is a special, pre-registered case. Its seed window was captured by
  hand on 2026-06-24 and Bitcoin-anchored *before* the engine's first
  classification, so past windows can be reconstructed and published.
- **ENTSO-E and NOAA (NDBC)** have no equivalent. Their buffers are trimmed on
  every tick and only the `input_hash` was ever stored — never the points.
  Their past therefore survives **only as a commitment (hash)**, which is
  irrecoverable by design. No upload can reopen it; this is documented, not
  fixed.
- **Going forward**, from a defined start date the client will persist every
  dispatched vector, so all three domains will publish exact vectors from that
  date on. Before it: hash only. After it: hash **and** vector.

Published so far:

- `nasa_seed_vector.json` — the NASA:GLOBAL seed window (1976-06 → 2026-05),
  captured 2026-06-24, Bitcoin-anchored **before** the engine's first
  classification. A pre-registration.
- `nasa_vector_2026-07-16.json` — the exact 600-point window the engine
  classified at dispatch 2026-07-16T12:00:13Z (1976-07 → 2026-06). 599 of its
  points are identical to the seed; the only new point is 2026-06, frozen by
  first-write-wins.

**File integrity.** The published `.json` file itself is sealed by its `.ots`
proof; its SHA-256 (`sha256sum <name>.json`) is what the OpenTimestamps proof
covers. Note this is a *different* hash from the `input_hash` above: the first
is the hash of the file as published, the second is the engine's hash over the
600 values. They are not expected to match.
