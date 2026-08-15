#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
digest_daily.py — HIMI public ledger daily digest

WHAT IT DOES (and what it does NOT)
-----------------------------------
A read-only pass over the public set of entries (same pattern as
snapshot_public.py: zero network, zero concurrency) that writes ONE new line
to an append-only JSONL file:  digest_ledger.jsonl

Each line ("digest record") is a cryptographic commitment for the day:
  - entry_count : cumulative count of public entries        -> detects deletions/additions
  - merkle_root : Merkle root (RFC 6962) over the per-entry hashes,
                  IN ORDER                                   -> detects modification and reordering
  - prev_digest_hash : digest_hash of the previous line      -> daily chain (chaining)
  - digest_hash : SHA-256 of the record itself (canonical)   -> identity + next prev

SCOPE HONESTY (say it before an auditor does):
  - The Merkle leaf is each entry's result_hash, in the ledger's PHYSICAL WRITE
    ORDER. The root inherits exactly the coverage of compute_result_hash's canonical
    payload.
  - COVERAGE (precise, promising no more): the OFFICIAL root (OTS-sealed) is
    over the COMPLETE LEDGER, exactly as published in public_hashes.jsonl (physical
    order, complete). The row-by-row recomputation the BROWSER does in the Ledger tab
    is a SEPARATE spot-check, limited to the window that carries vectors
    (ledger_recent.json, 500/node) -> it does NOT cover everything the root covers. They are
    two complementary things: rebuilding the root needs only the hashes in
    public_hashes.jsonl; recomputing each result_hash needs the vectors, which
    are published only for the recent window. Both roots must be labelled
    (official = complete ledger; merkle_root_recent = window) so they are not confused.
  - It DOES prove: the SET, the ORDER and the CONTENT (via result_hash) of the
    entries are fixed and reproducible by anyone who downloads
    public_hashes.jsonl (no vectors needed to rebuild the root).
  - It does NOT prove: that the source data was "correct" in the real world, nor anything
    inside the intra-day window before external anchoring (GitHub + OpenTimestamps).

REPRODUCIBILITY
---------------
Anyone who downloads public_hashes.jsonl can:
  1. take the result_hash of each row, in order,
  2. build the root with the RFC 6962 algorithm below,
  3. compare it with the published merkle_root (on GitHub / OpenTimestamps).
No value is invented.

The script does NO network. The git push and the `ots stamp` are SEPARATE steps in the
systemd wrapper / timer (same philosophy as the push to Cloudflare).

USAGE
-----
  source /opt/himi/.env  # if --source depends on paths from .env
  python3 digest_daily.py --source <hashes_or_public_ledger_file> \
                    --out /opt/himi/data/digest_ledger.jsonl

  python3 digest_daily.py --verify --out /opt/himi/data/digest_ledger.jsonl
  python3 digest_daily.py --selftest
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(leaves):
    """RFC 6962 Merkle Tree Hash over a list of bytes (the leaves).

    MTH({})      = SHA-256("")
    MTH({d0})    = SHA-256(0x00 || d0)
    MTH(D[n>1])  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                   with k = largest power of two strictly < n.

    The 0x00 (leaf) / 0x01 (node) prefix is the domain separation from
    Certificate Transparency: prevents second-preimage attacks between levels.
    """
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return sha256(b"\x00" + leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return sha256(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:]))


# --------------------------------------------------------------------------
# Reading the public set of entries
# --------------------------------------------------------------------------

def load_leaf_hashes(path, field="result_hash"):
    """Returns the ORDERED list of hashes (hex) of the public entries.

    >>> SINGLE INTEGRATION POINT <<<
    `path` must point to the public_hashes.jsonl that emit_public_hashes.py emits, which
    reads the INTERNAL LEDGER (/opt/himi/data/gr7_track_record.json, JSONL,
    physical order, complete) and derives {"result_hash": "..."} per entry in order.
    This same file is the one published to Cloudflare and anchored: so you get
    both "what I seal is exactly what you see" (a downloadable public file)
    and the determinism of the internal ledger's physical order. Note: this set is
    the COMPLETE LEDGER, not the 500/node window of ledger_recent.json.

    Accepted formats (auto-detection):
      - .jsonl : one JSON object per line -> `field` is extracted
      - .json  : array of objects, or {"entries":[...]}  -> `field` is extracted
      - plain text: one hex hash per line
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    stripped = raw.strip()
    if not stripped:
        return []

    # Try 1: whole JSON (array or object with "entries")
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict) and "entries" in obj:
            obj = obj["entries"]
        if isinstance(obj, list):
            return [str(_extract(e, field)) for e in obj]
    except json.JSONDecodeError:
        pass

    # Try 2: JSONL or plain text (one thing per line)
    out = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            out.append(str(_extract(e, field)))
        except json.JSONDecodeError:
            out.append(line)  # plain text: the line IS the hash
    return out


def _extract(entry, field):
    if isinstance(entry, dict):
        if field not in entry:
            raise KeyError(
                f"Entry without field '{field}'. Available keys: "
                f"{list(entry.keys())}"
            )
        return entry[field]
    # if the entry is already a string (plain hash)
    return entry


# --------------------------------------------------------------------------
# Digest record + chain
# --------------------------------------------------------------------------

LEAF_SOURCE = "per_entry_result_hash"
MERKLE_SPEC = "rfc6962-sha256"


def _canonical(record_without_digest_hash):
    """Deterministic canonical serialization (keys sorted, no spaces)."""
    return json.dumps(
        record_without_digest_hash, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def build_record(hashes, prev_digest_hash, computed_at):
    leaves = [h.encode("utf-8") for h in hashes]  # leaf = result_hash hex (utf-8)
    root_hex = merkle_root(leaves).hex()
    record = {
        "computed_at": computed_at,
        "entry_count": len(hashes),
        "merkle_root": root_hex,
        "prev_digest_hash": prev_digest_hash,  # None for the genesis
        "leaf_source": LEAF_SOURCE,
        "merkle_spec": MERKLE_SPEC,
    }
    record["digest_hash"] = sha256(_canonical(record)).hex()
    return record


def read_last_digest_hash(out_path):
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        return None
    last = None
    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return None
    return json.loads(last)["digest_hash"]


def atomic_append_line(out_path, line):
    """Append-only via full atomic rewrite (.tmp + os.replace).

    The file is tiny (1 line/day). Rewriting it whole guarantees that no
    half-written line is ever left if the process is cut off (your atomic-
    operation rule)."""
    existing = ""
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            existing = f.read()
    if existing and not existing.endswith("\n"):
        existing += "\n"
    new_content = existing + line + "\n"

    d = os.path.dirname(os.path.abspath(out_path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".digest_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# --------------------------------------------------------------------------
# Chain verification (auditor tool)
# --------------------------------------------------------------------------

def verify_chain(out_path):
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        print("Empty or nonexistent digest file.")
        return True
    prev = None
    n = 0
    with open(out_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            stored = rec.pop("digest_hash")
            recomputed = sha256(_canonical(rec)).hex()
            if recomputed != stored:
                print(f"[FAIL] line {i}: digest_hash does not match "
                      f"(expected {recomputed[:12]}..., written {stored[:12]}...)")
                return False
            if rec["prev_digest_hash"] != prev:
                print(f"[FAIL] line {i}: broken chain "
                      f"(prev written {str(rec['prev_digest_hash'])[:12]}..., "
                      f"actual {str(prev)[:12]}...)")
                return False
            prev = stored
            n += 1
    print(f"[OK] valid chain: {n} record(s), final root {prev[:16]}...")
    return True


# --------------------------------------------------------------------------
# Self-test (tests the logic without touching anything in production)
# --------------------------------------------------------------------------

def selftest():
    print("=== SELF-TEST digest_daily.py ===\n")
    tmpdir = tempfile.mkdtemp(prefix="himi_digest_selftest_")
    src = os.path.join(tmpdir, "public_hashes.jsonl")
    out = os.path.join(tmpdir, "digest_ledger.jsonl")

    # --- Reference Merkle (computed by hand for n=2) ---
    a = "aa" * 32
    b = "bb" * 32
    la, lb = a.encode(), b.encode()
    ref = sha256(b"\x01" + sha256(b"\x00" + la) + sha256(b"\x00" + lb)).hex()
    got = merkle_root([la, lb]).hex()
    assert got == ref, "Merkle n=2 does not match"
    print(f"[OK] Merkle n=2 reproducible by hand: {got[:16]}...")

    # n=1 and n=0
    assert merkle_root([la]).hex() == sha256(b"\x00" + la).hex()
    assert merkle_root([]).hex() == sha256(b"").hex()
    print("[OK] edge cases n=0 and n=1 correct")

    # --- DAY 1: 3 entries ---
    with open(src, "w") as f:
        for h in [a, b, "cc" * 32]:
            f.write(json.dumps({"result_hash": h, "asset_id": "X"}) + "\n")
    hashes = load_leaf_hashes(src)
    assert hashes == [a, b, "cc" * 32], "incorrect leaf reading"
    rec1 = build_record(hashes, prev_digest_hash=read_last_digest_hash(out),
                        computed_at="2026-06-30T23:59:00Z")
    atomic_append_line(out, json.dumps(rec1, sort_keys=True, separators=(",", ":")))
    assert rec1["prev_digest_hash"] is None, "genesis should have prev=None"
    assert rec1["entry_count"] == 3
    print(f"[OK] day 1: count=3, root={rec1['merkle_root'][:16]}..., "
          f"digest={rec1['digest_hash'][:16]}...")

    # --- DAY 2: 5 entries (2 added) ---
    with open(src, "w") as f:
        for h in [a, b, "cc" * 32, "dd" * 32, "ee" * 32]:
            f.write(json.dumps({"result_hash": h}) + "\n")
    hashes = load_leaf_hashes(src)
    rec2 = build_record(hashes, prev_digest_hash=read_last_digest_hash(out),
                        computed_at="2026-07-01T23:59:00Z")
    atomic_append_line(out, json.dumps(rec2, sort_keys=True, separators=(",", ":")))
    assert rec2["prev_digest_hash"] == rec1["digest_hash"], "chain does not link"
    assert rec2["entry_count"] == 5
    print(f"[OK] day 2: count=5, prev links with day 1, "
          f"root={rec2['merkle_root'][:16]}...")

    # --- Chain verification ---
    print()
    assert verify_chain(out), "verify_chain should pass"

    # --- Tamper detection ---
    print("\n--- tamper test (verification must FAIL) ---")
    lines = open(out).read().splitlines()
    tampered = json.loads(lines[0])
    tampered["entry_count"] = 999  # we touch the past
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    bad = os.path.join(tmpdir, "tampered.jsonl")
    open(bad, "w").write("\n".join(lines) + "\n")
    assert verify_chain(bad) is False, "hauria de detectar la manipulacio"

    print("\n=== ALL TESTS OK ===")
    print(f"(temporary artifacts in {tmpdir})")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="HIMI daily digest (Merkle + chain)")
    p.add_argument("--source", help="public set file (hashes/ledger)")
    p.add_argument("--field", default="result_hash",
                   help="hash field per entry (default: result_hash)")
    p.add_argument("--out", default="/opt/himi/data/digest_ledger.jsonl",
                   help="append-only JSONL file of digests")
    p.add_argument("--verify", action="store_true",
                   help="verify the chain of the --out file and exit")
    p.add_argument("--selftest", action="store_true", help="internal test and exit")
    args = p.parse_args()

    if args.selftest:
        selftest()
        return
    if args.verify:
        sys.exit(0 if verify_chain(args.out) else 1)

    if not args.source:
        p.error("need --source (or use --selftest / --verify)")

    hashes = load_leaf_hashes(args.source, field=args.field)
    prev = read_last_digest_hash(args.out)
    computed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = build_record(hashes, prev_digest_hash=prev, computed_at=computed_at)
    atomic_append_line(
        args.out, json.dumps(record, sort_keys=True, separators=(",", ":"))
    )
    print(f"digest written: count={record['entry_count']} "
          f"root={record['merkle_root']} digest={record['digest_hash']}")


if __name__ == "__main__":
    main()
    
    