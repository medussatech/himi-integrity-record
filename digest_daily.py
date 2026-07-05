#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
digest_daily.py  —  HIMI public ledger daily digest

QUE FA (i que NO fa)
--------------------
Una passada de lectura del conjunt public d'entrades (mateix patro que
snapshot_public.py: zero xarxa, zero concurrencia) i escriu UNA linia nova
a un fitxer JSONL append-only:  digest_ledger.jsonl

Cada linia ("digest record") es un compromis criptografic del dia:
  - entry_count : nombre cumulatiu d'entrades publiques  -> detecta esborrats/afegits
  - merkle_root : arrel de Merkle (RFC 6962) sobre els hashes per-entrada,
                  EN ORDRE                                 -> detecta modificacio i reordenacio
  - prev_digest_hash : digest_hash de la linia anterior    -> cadena diaria (chaining)
  - digest_hash : SHA-256 del propi record (canonic)       -> identitat + seguent prev

ABAST HONEST (dir-ho abans que ho digui un auditor):
  - La fulla de Merkle es el result_hash de cada entrada, en ORDRE FISIC
    d'escriptura del ledger. L'arrel hereta exactament la cobertura del canonical
    payload de compute_result_hash.
  - COBERTURA (afinat, no prometre de mes): l'arrel OFICIAL (OTS-segellada) es
    sobre el LEDGER SENCER, tal com es publica a public_hashes.jsonl (ordre fisic,
    complet). La recomputacio fila-a-fila que fa el NAVEGADOR a la pestanya Ledger
    es un spot-check SEPARAT i limitat a la finestra que porti vectors
    (ledger_recent.json, 500/node) -> NO cobreix tot el que cobreix l'arrel. Son
    dues coses complementaries: reconstruir l'arrel nomes necessita els hashes de
    public_hashes.jsonl; recalcular cada result_hash necessita els vectors, que
    nomes es publiquen per a la finestra recent. Cal etiquetar els dos roots
    (oficial = ledger sencer; merkle_root_recent = finestra) perque no es confonguin.
  - Aixo demostra: el CONJUNT, l'ORDRE i el CONTINGUT (via result_hash) de les
    entrades estan fixats i son reproduibles per qualsevol que baixi
    public_hashes.jsonl (no li calen els vectors per reconstruir l'arrel).
  - NO demostra: que les dades d'origen fossin "correctes" del mon real, ni res
    dins la finestra intra-dia abans de l'ancoratge extern (GitHub + OpenTimestamps).

REPRODUCTIBILITAT
-----------------
Qualsevol que descarregui el public_hashes.jsonl pot:
  1. agafar el result_hash de cada fila, en ordre,
  2. construir l'arrel amb l'algoritme RFC 6962 d'aqui sota,
  3. comparar amb el merkle_root publicat (a GitHub / OpenTimestamps).
Cap valor s'inventa.

L'script NO fa xarxa. El git push i el `ots stamp` son passos SEPARATS al
wrapper / timer de systemd (mateixa filosofia que el push a Cloudflare).

US
--
  source /opt/himi/.env  # si el --source depen de rutes del .env
  python3 digest_daily.py --source <fitxer_hashes_o_ledger_public> \
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
    """RFC 6962 Merkle Tree Hash sobre una llista de bytes (les fulles).

    MTH({})      = SHA-256("")
    MTH({d0})    = SHA-256(0x00 || d0)
    MTH(D[n>1])  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                   amb k = potencia de dos mes gran estrictament < n.

    El prefix 0x00 (fulla) / 0x01 (node) es la separacio de domini de
    Certificate Transparency: evita atacs de segona preimatge entre nivells.
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
# Lectura del conjunt public d'entrades
# --------------------------------------------------------------------------

def load_leaf_hashes(path, field="result_hash"):
    """Retorna la llista ORDENADA de hashes (hex) de les entrades publiques.

    >>> PUNT D'INTEGRACIO UNIC <<<
    `path` ha d'apuntar al public_hashes.jsonl que emet emit_public_hashes.py, el
    qual llegeix el LEDGER INTERN (/opt/himi/data/gr7_track_record.json, JSONL,
    ordre fisic, sencer) i deriva {"result_hash": "..."} per entrada en ordre.
    Aquest mateix fitxer es el que es publica a Cloudflare i s'ancora: aixi tens
    alhora "el que segello es exactament el que veus" (fitxer public descarregable)
    i el determinisme de l'ordre fisic del ledger intern. Nota: aquest conjunt es
    el LEDGER SENCER, no la finestra 500/node de ledger_recent.json.

    Formats acceptats (auto-deteccio):
      - .jsonl  : un objecte JSON per linia -> s'extreu `field`
      - .json   : array d'objectes, o {"entries":[...]}  -> s'extreu `field`
      - text pla: un hash hex per linia
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    stripped = raw.strip()
    if not stripped:
        return []

    # Prova 1: JSON sencer (array o objecte amb "entries")
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict) and "entries" in obj:
            obj = obj["entries"]
        if isinstance(obj, list):
            return [str(_extract(e, field)) for e in obj]
    except json.JSONDecodeError:
        pass

    # Prova 2: JSONL o text pla (una cosa per linia)
    out = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            out.append(str(_extract(e, field)))
        except json.JSONDecodeError:
            out.append(line)  # text pla: la linia ES el hash
    return out


def _extract(entry, field):
    if isinstance(entry, dict):
        if field not in entry:
            raise KeyError(
                f"Entrada sense camp '{field}'. Claus disponibles: "
                f"{list(entry.keys())}"
            )
        return entry[field]
    # si l'entrada ja es un string (hash pla)
    return entry


# --------------------------------------------------------------------------
# Record del digest + cadena
# --------------------------------------------------------------------------

LEAF_SOURCE = "per_entry_result_hash"
MERKLE_SPEC = "rfc6962-sha256"


def _canonical(record_without_digest_hash):
    """Serialitzacio canonica deterministica (claus ordenades, sense espais)."""
    return json.dumps(
        record_without_digest_hash, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def build_record(hashes, prev_digest_hash, computed_at):
    leaves = [h.encode("utf-8") for h in hashes]  # fulla = result_hash hex (utf-8)
    root_hex = merkle_root(leaves).hex()
    record = {
        "computed_at": computed_at,
        "entry_count": len(hashes),
        "merkle_root": root_hex,
        "prev_digest_hash": prev_digest_hash,  # None per al genesi
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
    """Append-only via reescriptura atomica completa (.tmp + os.replace).

    El fitxer es minus (1 linia/dia). Reescriure'l sencer garanteix que mai
    quedi una linia a mig escriure si el proces es talla (la teva regla
    d'operacio atomica)."""
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
# Verificacio de la cadena (eina d'auditor)
# --------------------------------------------------------------------------

def verify_chain(out_path):
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        print("Fitxer de digest buit o inexistent.")
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
                print(f"[FAIL] linia {i}: digest_hash no quadra "
                      f"(esperat {recomputed[:12]}..., escrit {stored[:12]}...)")
                return False
            if rec["prev_digest_hash"] != prev:
                print(f"[FAIL] linia {i}: cadena trencada "
                      f"(prev escrit {str(rec['prev_digest_hash'])[:12]}..., "
                      f"real {str(prev)[:12]}...)")
                return False
            prev = stored
            n += 1
    print(f"[OK] cadena valida: {n} record(s), arrel final {prev[:16]}...")
    return True


# --------------------------------------------------------------------------
# Self-test (prova la logica sense tocar res de produccio)
# --------------------------------------------------------------------------

def selftest():
    print("=== SELF-TEST digest_daily.py ===\n")
    tmpdir = tempfile.mkdtemp(prefix="himi_digest_selftest_")
    src = os.path.join(tmpdir, "public_hashes.jsonl")
    out = os.path.join(tmpdir, "digest_ledger.jsonl")

    # --- Merkle de referencia (calculat a ma per n=2) ---
    a = "aa" * 32
    b = "bb" * 32
    la, lb = a.encode(), b.encode()
    ref = sha256(b"\x01" + sha256(b"\x00" + la) + sha256(b"\x00" + lb)).hex()
    got = merkle_root([la, lb]).hex()
    assert got == ref, "Merkle n=2 no quadra"
    print(f"[OK] Merkle n=2 reproduible a ma: {got[:16]}...")

    # n=1 i n=0
    assert merkle_root([la]).hex() == sha256(b"\x00" + la).hex()
    assert merkle_root([]).hex() == sha256(b"").hex()
    print("[OK] casos vora n=0 i n=1 correctes")

    # --- DIA 1: 3 entrades ---
    with open(src, "w") as f:
        for h in [a, b, "cc" * 32]:
            f.write(json.dumps({"result_hash": h, "asset_id": "X"}) + "\n")
    hashes = load_leaf_hashes(src)
    assert hashes == [a, b, "cc" * 32], "lectura de fulles incorrecta"
    rec1 = build_record(hashes, prev_digest_hash=read_last_digest_hash(out),
                        computed_at="2026-06-30T23:59:00Z")
    atomic_append_line(out, json.dumps(rec1, sort_keys=True, separators=(",", ":")))
    assert rec1["prev_digest_hash"] is None, "genesi hauria de tenir prev=None"
    assert rec1["entry_count"] == 3
    print(f"[OK] dia 1: count=3, root={rec1['merkle_root'][:16]}..., "
          f"digest={rec1['digest_hash'][:16]}...")

    # --- DIA 2: 5 entrades (afegides 2) ---
    with open(src, "w") as f:
        for h in [a, b, "cc" * 32, "dd" * 32, "ee" * 32]:
            f.write(json.dumps({"result_hash": h}) + "\n")
    hashes = load_leaf_hashes(src)
    rec2 = build_record(hashes, prev_digest_hash=read_last_digest_hash(out),
                        computed_at="2026-07-01T23:59:00Z")
    atomic_append_line(out, json.dumps(rec2, sort_keys=True, separators=(",", ":")))
    assert rec2["prev_digest_hash"] == rec1["digest_hash"], "cadena no enganxa"
    assert rec2["entry_count"] == 5
    print(f"[OK] dia 2: count=5, prev enganxa amb dia 1, "
          f"root={rec2['merkle_root'][:16]}...")

    # --- Verificacio de la cadena ---
    print()
    assert verify_chain(out), "verify_chain hauria de passar"

    # --- Deteccio de manipulacio ---
    print("\n--- prova de manipulacio (ha de FALLAR la verificacio) ---")
    lines = open(out).read().splitlines()
    tampered = json.loads(lines[0])
    tampered["entry_count"] = 999  # toquem el passat
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    bad = os.path.join(tmpdir, "tampered.jsonl")
    open(bad, "w").write("\n".join(lines) + "\n")
    assert verify_chain(bad) is False, "hauria de detectar la manipulacio"

    print("\n=== TOTS ELS TESTS OK ===")
    print(f"(artefactes temporals a {tmpdir})")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="HIMI daily digest (Merkle + chain)")
    p.add_argument("--source", help="fitxer del conjunt public (hashes/ledger)")
    p.add_argument("--field", default="result_hash",
                   help="camp del hash per entrada (default: result_hash)")
    p.add_argument("--out", default="/opt/himi/data/digest_ledger.jsonl",
                   help="fitxer JSONL append-only de digests")
    p.add_argument("--verify", action="store_true",
                   help="verifica la cadena del fitxer --out i surt")
    p.add_argument("--selftest", action="store_true", help="prova interna i surt")
    args = p.parse_args()

    if args.selftest:
        selftest()
        return
    if args.verify:
        sys.exit(0 if verify_chain(args.out) else 1)

    if not args.source:
        p.error("cal --source (o usa --selftest / --verify)")

    hashes = load_leaf_hashes(args.source, field=args.field)
    prev = read_last_digest_hash(args.out)
    computed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = build_record(hashes, prev_digest_hash=prev, computed_at=computed_at)
    atomic_append_line(
        args.out, json.dumps(record, sort_keys=True, separators=(",", ":"))
    )
    print(f"digest escrit: count={record['entry_count']} "
          f"root={record['merkle_root']} digest={record['digest_hash']}")


if __name__ == "__main__":
    main()
    
    