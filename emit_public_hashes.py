#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
emit_public_hashes.py  —  derives HIMI's public_hashes.jsonl sidecar

PURPOSE
-------
Derive `public_hashes.jsonl` (the result_hash of ALL ledger entries,
IN PHYSICAL WRITE ORDER) by reading VPS1's INTERNAL ledger DIRECTLY:

    /opt/himi/data/gr7_track_record.json   (JSONL, one entry per line, complete)

This derived file is the one PUBLISHED to Cloudflare and the one ANCHORED (OTS).

WHY THIS WAY (A->B synthesis, decided with eyes open)
-----------------------------------------------------
A and B looked mutually exclusive:
  - A (anchor the internal one): perfect physical order, but the public can't see it byte-for-byte.
  - B (anchor the public one): stronger for an auditor, but ledger_recent.json is
    GROUPED by node and trimmed to 500/node -> neither order nor the complete set.

The synthesis makes them converge into ONE single file:
  1. We read A's source: the internal ledger, JSONL, PHYSICAL ORDER, COMPLETE.
     Physical order (not the timestamp) is the canonical truth of the whole experiment:
     first-write-wins / resolve-once / no-backfilling / no-imputation. The
     timestamps TIE between entries of the same dispatch tick (verified in the
     real file: two entries with timestamp 1783088707), so ordering by
     timestamp would be incorrect. Line order is the only truth.
  2. We emit the derived `public_hashes.jsonl` and PUBLISH it to Cloudflare.
     It is downloadable -> "what I seal is exactly what you see" (B's strength).
  3. Each leaf is the `result_hash` the browser already knows how to recompute row by row.
     The auditor need not trust anything: takes the published hashes, orders them
     as they are, builds the Merkle root and compares it with the anchored one (OTS).

SCOPE HONESTY (essential, do not conflate)
------------------------------------------
  - `public_hashes.jsonl` covers the WHOLE LEDGER -> the official Merkle root
    (OTS-sealed) is over ALL entries in physical order.
  - `ledger_recent.json` (500/node window, grouped) is NOT the source of this file.
    Its `merkle_root_recent` is ONLY informative. Both roots must be labelled
    so an auditor does not confuse them.
  - The browser's row-by-row recomputation (verifying that each result_hash is a
    genuine HIMI output) is a SEPARATE check, limited to the vectors that get published;
    the Merkle-root verification, by contrast, needs only this file.
  - What the root attests: 600 genuine observations per vector, no imputation.
  - VPS2's experiment_ledger.jsonl (same result_hash, cross-witness) is NOT the
    source of the digest -> a future cross-verification improvement, not mixed in here.

Does NO network. Local read-only + one atomic write. Runs inside the same
wrapper, right after the snapshot and just before digest_daily.py:

    snapshot_public.py  ->  emit_public_hashes.py  ->  digest_daily.py  ->  git/ots

USAGE
-----
  python3 emit_public_hashes.py \
     --ledger /opt/himi/data/gr7_track_record.json \
     --out    /opt/medussa/public_snapshot/public_hashes.jsonl

  python3 emit_public_hashes.py --selftest

VERIFY-BEFORE-TOUCH at deployment:
  1. --ledger points to the INTERNAL JSONL ledger (NOT the grouped ledger_recent.json).
  2. the per-entry hash field is `result_hash` (confirmed in the real file, 3/7).
Acceptance test: the lines of public_hashes.jsonl == the TOTAL number of entries of the
internal ledger (order of magnitude ~2846+, NOT 15, NOT the 500/node window).
"""

import argparse
import json
import os
import tempfile


def load_ledger_hashes(path, field="result_hash"):
    """Ordered list (physical order) of the internal ledger's result_hash values.

    Tolerant auto-detection, but with an explicit guard against the WRONG source:
      - JSONL (the real case of gr7_track_record.json): one object per line.
      - JSON array of objects / {"entries":[...]}: accepted.
      - dict GROUPED BY NODE (ledger_recent.json): REJECTED with a clear error,
        because it is NOT the source of the digest (neither physical order nor the complete set).
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        return []

    # Try a whole JSON first (array, {"entries":[...]}, or a single entry).
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        obj = None  # multi-line -> JSONL, the normal case of the internal ledger

    if obj is not None:
        if isinstance(obj, dict) and "entries" in obj:
            obj = obj["entries"]
        if isinstance(obj, list):
            return [str(_field(e, field)) for e in obj]
        if isinstance(obj, dict):
            if field in obj:
                # single-line file = one single entry
                return [str(obj[field])]
            # dict without the hash field -> most probably GROUPED BY NODE
            raise ValueError(
                "The file looks like a ledger GROUPED BY NODE (keys="
                f"{list(obj.keys())[:4]}). This is NOT the source of the digest. "
                "Point to /opt/himi/data/gr7_track_record.json "
                "(JSONL, physical order, complete)."
            )

    # JSONL: one object per line -> line order = physical order = canonical truth.
    out = []
    for i, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Line {i} is not valid JSON; the file does not look like clean JSONL. "
                f"Detail: {e}"
            )
        out.append(str(_field(entry, field)))
    return out


def _field(entry, field):
    if isinstance(entry, dict):
        if field not in entry:
            raise KeyError(
                f"Entry without field '{field}'. Keys: {list(entry.keys())}"
            )
        return entry[field]
    return entry  # already a string


def atomic_write(path, content):
    """.tmp -> flush -> fsync -> os.replace. Same discipline as snapshot_public.py."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pubhash_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def emit(ledger_path, out_path, field="result_hash"):
    """Derives public_hashes.jsonl from the internal ledger, in physical order.

    Output schema INTACT with respect to the previous version: one line per entry,
    {"result_hash": h}, canonical serialization. The contract with
    digest_daily.py (which reads this field) is not touched.
    """
    hashes = load_ledger_hashes(ledger_path, field=field)
    lines = [json.dumps({"result_hash": h}, separators=(",", ":")) for h in hashes]
    payload = "\n".join(lines) + ("\n" if lines else "")
    atomic_write(out_path, payload)
    return len(hashes)


def selftest():
    print("=== SELF-TEST emit_public_hashes.py ===\n")
    tmp = tempfile.mkdtemp(prefix="himi_pubhash_selftest_")
    a, b, c = "aa" * 32, "bb" * 32, "cc" * 32

    # case 1: array of objects
    p1 = os.path.join(tmp, "ledger_array.json")
    json.dump(
        [{"result_hash": a, "asset_id": "X"},
         {"result_hash": b, "asset_id": "Y"},
         {"result_hash": c, "asset_id": "Z"}],
        open(p1, "w"),
    )
    o1 = os.path.join(tmp, "out_array.jsonl")
    n = emit(p1, o1)
    got = [json.loads(l)["result_hash"] for l in open(o1).read().splitlines()]
    assert n == 3 and got == [a, b, c], "array: wrong order/set"
    print(f"[OK] array of objects -> {n} hashes, order preserved")

    # case 2: {"entries":[...]}
    p2 = os.path.join(tmp, "ledger_entries.json")
    json.dump({"entries": [{"result_hash": a}, {"result_hash": b}]}, open(p2, "w"))
    o2 = os.path.join(tmp, "out_entries.jsonl")
    n = emit(p2, o2)
    assert n == 2, "entries: wrong count"
    print(f"[OK] {{'entries':[...]}} -> {n} hashes")

    # case 3: simple JSONL (logic reused from the previous version)
    p3 = os.path.join(tmp, "ledger.jsonl")
    with open(p3, "w") as f:
        for h in [a, b, c]:
            f.write(json.dumps({"result_hash": h}) + "\n")
    o3 = os.path.join(tmp, "out_jsonl.jsonl")
    n = emit(p3, o3)
    assert n == 3, "jsonl: wrong count"
    print(f"[OK] simple JSONL -> {n} hashes")

    # case 4: empty ledger -> empty file, no crash
    p4 = os.path.join(tmp, "empty.json")
    open(p4, "w").write("[]")
    o4 = os.path.join(tmp, "out_empty.jsonl")
    n = emit(p4, o4)
    assert n == 0 and open(o4).read() == "", "empty: should give an empty file"
    print("[OK] empty ledger -> 0 hashes, no error")

    # case 5: nonexistent field -> clear error
    p5 = os.path.join(tmp, "badfield.json")
    json.dump([{"hash_dolent": a}], open(p5, "w"))
    try:
        emit(p5, os.path.join(tmp, "x5.jsonl"))
        assert False, "should have thrown KeyError"
    except KeyError as e:
        print(f"[OK] nonexistent field -> explicit error: {str(e)[:48]}...")

    # case 6: REAL STRUCTURE (whole entries, SAME timestamp) -> physical order
    #        Replicates what is in gr7_track_record.json: two records with
    #        timestamp 1783088707. Must preserve LINE order, not sort.
    p6 = os.path.join(tmp, "real_like.jsonl")
    e1 = {"asset_id": "NOAA:44013:WTMP", "client_id": "experiment",
          "result_hash": a, "state": "Recovery Regime",
          "timestamp": 1783088707, "vector_length": 600}
    e2 = {"asset_id": "NOAA:44013:WSPD", "client_id": "experiment",
          "result_hash": b, "state": "Healthy Ignition",
          "timestamp": 1783088707, "vector_length": 600}
    with open(p6, "w") as f:
        f.write(json.dumps(e1) + "\n")
        f.write(json.dumps(e2) + "\n")
    o6 = os.path.join(tmp, "out_real.jsonl")
    n = emit(p6, o6)
    got = [json.loads(l)["result_hash"] for l in open(o6).read().splitlines()]
    assert n == 2 and got == [a, b], \
        "real: must preserve PHYSICAL ORDER, not reorder by timestamp"
    print(f"[OK] real structure (repeated timestamp) -> {n} hashes in physical order")

    # case 7: ledger GROUPED BY NODE -> REJECTED (not the source of the digest)
    p7 = os.path.join(tmp, "grouped.json")
    json.dump(
        {"NOAA:44013:WTMP": [{"result_hash": a}],
         "NOAA:44013:WSPD": [{"result_hash": b}]},
        open(p7, "w"),
    )
    try:
        emit(p7, os.path.join(tmp, "x7.jsonl"))
        assert False, "should have rejected the node-grouped ledger"
    except ValueError as e:
        print(f"[OK] grouped ledger rejected: {str(e)[:52]}...")

    print("\n=== ALL TESTS OK ===")
    print(f"(artifacts in {tmp})")


def main():
    p = argparse.ArgumentParser(
        description="Derives public_hashes.jsonl from the INTERNAL ledger (physical order, complete)"
    )
    p.add_argument("--ledger",
                   help="path of the INTERNAL JSONL ledger (/opt/himi/data/gr7_track_record.json)")
    p.add_argument("--field", default="result_hash",
                   help="hash field per entry (default: result_hash)")
    p.add_argument("--out", help="output path for public_hashes.jsonl")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        selftest()
        return
    if not args.ledger or not args.out:
        p.error("need --ledger and --out (or use --selftest)")

    n = emit(args.ledger, args.out, field=args.field)
    print(f"public_hashes.jsonl written: {n} entries (complete ledger, physical order) -> {args.out}")


if __name__ == "__main__":
    main()
    