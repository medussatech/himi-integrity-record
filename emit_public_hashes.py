#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
emit_public_hashes.py  —  derivador del sidecar public_hashes.jsonl de HIMI

OBJECTIU
--------
Derivar `public_hashes.jsonl` (els result_hash de TOTES les entrades del ledger,
EN ORDRE FISIC D'ESCRIPTURA) llegint DIRECTAMENT el ledger INTERN de VPS1:

    /opt/himi/data/gr7_track_record.json   (JSONL, una entrada per linia, sencer)

Aquest fitxer derivat es el que es PUBLICA a Cloudflare i el que s'ANCORA (OTS).

PER QUE AIXI (sintesi A->B, decidida amb els ulls oberts)
---------------------------------------------------------
A i B semblaven excloents:
  - A (ancorar l'intern): ordre fisic perfecte, pero el public no ho veu byte-a-byte.
  - B (ancorar el public): mes fort per un auditor, pero ledger_recent.json esta
    AGRUPAT per node i retallat a 500/node -> ni ordre ni conjunt sencer.

La sintesi les fa convergir en UN sol fitxer:
  1. Llegim la font d'A: el ledger intern, JSONL, ORDRE FISIC, SENCER.
     L'ordre fisic (no el timestamp) es la veritat canonica de tot l'experiment:
     first-write-wins / resolve-once / no-backfilling / no-imputation. Els
     timestamps EMPATEN entre entrades del mateix tick de dispatch (verificat al
     fitxer real: dues entrades amb timestamp 1783088707), aixi que ordenar per
     timestamp seria incorrecte. L'ordre de linia es l'unica veritat.
  2. Emetem `public_hashes.jsonl` derivat i el PUBLIQUEM a Cloudflare.
     Es descarregable -> "el que segello es exactament el que veus" (la forca de B).
  3. Cada fulla es el `result_hash` que el navegador ja sap recalcular fila a fila.
     L'auditor no ha de confiar en res: agafa els hashes publicats, els ordena tal
     com estan, construeix l'arrel Merkle i la compara amb l'ancorada (OTS).

HONESTEDAT D'ABAST (imprescindible, no barrejar)
-----------------------------------------------
  - `public_hashes.jsonl` cobreix el LEDGER SENCER -> l'arrel Merkle oficial
    (OTS-segellada) es sobre TOTES les entrades en ordre fisic.
  - `ledger_recent.json` (finestra 500/node, agrupat) NO es la font d'aquest fitxer.
    La seva `merkle_root_recent` es NOMES informativa. Cal etiquetar els dos roots
    perque un auditor no els confongui.
  - La recomputacio fila-a-fila del navegador (verificar que cada result_hash es un
    output HIMI genui) es un check SEPARAT i limitat als vectors que es publiquin;
    la verificacio del root Merkle, en canvi, nomes necessita aquest fitxer.
  - El que atesta l'arrel: 600 observacions genuines per vector, sense imputacio.
  - El experiment_ledger.jsonl de VPS2 (mateix result_hash, testimoni creuat) NO es
    font del digest -> millora de verificacio creuada de futur, no es barreja aqui.

NO fa xarxa. Lectura local read-only + una escriptura atomica. Corre dins el mateix
wrapper, just despres del snapshot i just abans de digest_daily.py:

    snapshot_public.py  ->  emit_public_hashes.py  ->  digest_daily.py  ->  git/ots

US
--
  python3 emit_public_hashes.py \
      --ledger /opt/himi/data/gr7_track_record.json \
      --out    /opt/medussa/public_snapshot/public_hashes.jsonl

  python3 emit_public_hashes.py --selftest

VERIFY-BEFORE-TOUCH al desplegament:
  1. --ledger apunta al ledger INTERN JSONL (NO al ledger_recent.json agrupat).
  2. el camp del hash per entrada es `result_hash` (confirmat al fitxer real 3/7).
Test d'acceptacio: les linies de public_hashes.jsonl == nombre TOTAL d'entrades del
ledger intern (ordre de magnitud ~2846+, NO 15, NO la finestra 500/node).
"""

import argparse
import json
import os
import tempfile


def load_ledger_hashes(path, field="result_hash"):
    """Llista ORDENADA (ordre fisic) dels result_hash del ledger intern.

    Auto-deteccio tolerant, pero amb guarda explicita contra la font EQUIVOCADA:
      - JSONL (cas real de gr7_track_record.json): un objecte per linia.
      - array JSON d'objectes / {"entries":[...]}: acceptat.
      - dict AGRUPAT PER NODE (ledger_recent.json): REBUTJAT amb error clar,
        perque NO es la font del digest (ni ordre fisic ni conjunt sencer).
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        return []

    # Provem primer un JSON sencer (array, {"entries":[...]}, o una sola entrada).
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        obj = None  # es multi-linia -> JSONL, el cas normal del ledger intern

    if obj is not None:
        if isinstance(obj, dict) and "entries" in obj:
            obj = obj["entries"]
        if isinstance(obj, list):
            return [str(_field(e, field)) for e in obj]
        if isinstance(obj, dict):
            if field in obj:
                # fitxer d'una sola linia = una unica entrada
                return [str(obj[field])]
            # dict sense el camp del hash -> molt probablement AGRUPAT PER NODE
            raise ValueError(
                "El fitxer sembla un ledger AGRUPAT PER NODE (claus="
                f"{list(obj.keys())[:4]}). Aixo NO es la font del digest. "
                "Apunta a /opt/himi/data/gr7_track_record.json "
                "(JSONL, ordre fisic, sencer)."
            )

    # JSONL: un objecte per linia -> ordre de linia = ordre fisic = veritat canonica.
    out = []
    for i, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Linia {i} no es JSON valid; el fitxer no sembla JSONL net. "
                f"Detall: {e}"
            )
        out.append(str(_field(entry, field)))
    return out


def _field(entry, field):
    if isinstance(entry, dict):
        if field not in entry:
            raise KeyError(
                f"Entrada sense camp '{field}'. Claus: {list(entry.keys())}"
            )
        return entry[field]
    return entry  # ja es un string


def atomic_write(path, content):
    """.tmp -> flush -> fsync -> os.replace. Mateixa disciplina que snapshot_public.py."""
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
    """Deriva public_hashes.jsonl del ledger intern, en ordre fisic.

    Esquema de sortida INTACTE respecte la versio anterior: una linia per entrada,
    {"result_hash": h}, serialitzacio canonica. No es toca el contracte amb
    digest_daily.py (que llegeix aquest camp).
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

    # cas 1: array d'objectes
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
    assert n == 3 and got == [a, b, c], "array: ordre/conjunt incorrecte"
    print(f"[OK] array d'objectes -> {n} hashes, ordre preservat")

    # cas 2: {"entries":[...]}
    p2 = os.path.join(tmp, "ledger_entries.json")
    json.dump({"entries": [{"result_hash": a}, {"result_hash": b}]}, open(p2, "w"))
    o2 = os.path.join(tmp, "out_entries.jsonl")
    n = emit(p2, o2)
    assert n == 2, "entries: compte incorrecte"
    print(f"[OK] {{'entries':[...]}} -> {n} hashes")

    # cas 3: JSONL simple (logica aprofitada de la versio anterior)
    p3 = os.path.join(tmp, "ledger.jsonl")
    with open(p3, "w") as f:
        for h in [a, b, c]:
            f.write(json.dumps({"result_hash": h}) + "\n")
    o3 = os.path.join(tmp, "out_jsonl.jsonl")
    n = emit(p3, o3)
    assert n == 3, "jsonl: compte incorrecte"
    print(f"[OK] JSONL simple -> {n} hashes")

    # cas 4: ledger buit -> fitxer buit, sense petar
    p4 = os.path.join(tmp, "empty.json")
    open(p4, "w").write("[]")
    o4 = os.path.join(tmp, "out_empty.jsonl")
    n = emit(p4, o4)
    assert n == 0 and open(o4).read() == "", "buit: hauria de donar fitxer buit"
    print("[OK] ledger buit -> 0 hashes, sense error")

    # cas 5: camp inexistent -> error clar
    p5 = os.path.join(tmp, "badfield.json")
    json.dump([{"hash_dolent": a}], open(p5, "w"))
    try:
        emit(p5, os.path.join(tmp, "x5.jsonl"))
        assert False, "hauria d'haver llencat KeyError"
    except KeyError as e:
        print(f"[OK] camp inexistent -> error explicit: {str(e)[:48]}...")

    # cas 6: ESTRUCTURA REAL (entrades senceres, MATEIX timestamp) -> ordre fisic
    #        Replica el que hi ha a gr7_track_record.json: dos registres amb
    #        timestamp 1783088707. Ha de preservar l'ordre de LINIA, no ordenar.
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
        "real: ha de preservar ORDRE FISIC, no reordenar per timestamp"
    print(f"[OK] estructura real (timestamp repetit) -> {n} hashes en ordre fisic")

    # cas 7: ledger AGRUPAT PER NODE -> REBUTJAT (no es la font del digest)
    p7 = os.path.join(tmp, "grouped.json")
    json.dump(
        {"NOAA:44013:WTMP": [{"result_hash": a}],
         "NOAA:44013:WSPD": [{"result_hash": b}]},
        open(p7, "w"),
    )
    try:
        emit(p7, os.path.join(tmp, "x7.jsonl"))
        assert False, "hauria d'haver rebutjat el ledger agrupat per node"
    except ValueError as e:
        print(f"[OK] ledger agrupat rebutjat: {str(e)[:52]}...")

    print("\n=== TOTS ELS TESTS OK ===")
    print(f"(artefactes a {tmp})")


def main():
    p = argparse.ArgumentParser(
        description="Deriva public_hashes.jsonl del ledger INTERN (ordre fisic, sencer)"
    )
    p.add_argument("--ledger",
                   help="path del ledger INTERN JSONL (/opt/himi/data/gr7_track_record.json)")
    p.add_argument("--field", default="result_hash",
                   help="camp del hash per entrada (default: result_hash)")
    p.add_argument("--out", help="path de sortida public_hashes.jsonl")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        selftest()
        return
    if not args.ledger or not args.out:
        p.error("cal --ledger i --out (o usa --selftest)")

    n = emit(args.ledger, args.out, field=args.field)
    print(f"public_hashes.jsonl escrit: {n} entrades (ledger sencer, ordre fisic) -> {args.out}")


if __name__ == "__main__":
    main()
    