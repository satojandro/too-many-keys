#!/usr/bin/env python3
"""
near-keys.py — audit and prune access keys on a NEAR account that has grown
past the RPC's 100-key limit (the "TOO_MANY_ACCESS_KEYS" / "can't log in to
near.social" failure).

Two subcommands:

  list   Read-only. Pages through view_access_key_list with limit/after_key,
         pins every page to one block, groups keys by receiver contract, and
         works out when each key last signed using the block height encoded in
         its nonce (real block timestamps from the archival RPC, cached).

  clean  Deletes function-call keys in batches — many DeleteKey actions inside
         one transaction — signed locally with an ed25519 full-access key.
         Dry-run by default. Never touches full-access keys unless you pass
         --allow-full-access, and never deletes the last full-access key.

Notes that matter:
  * Only 32-byte ed25519 keys are supported (secp256k1 keys must be left alone).
  * The signer must be a full-access key on the SAME account (DeleteKey acts on
    the signer's own account, so receiver_id == signer_id).
  * Dry-run first. Every batch is verified against the RPC afterwards.
  * Deps: none. Python 3.9+ stdlib only (ed25519 and base58 are implemented
    below so this runs identically on any machine).

Usage:
  python3 near-keys.py list someone.near
  python3 near-keys.py list someone.near --csv keys.csv

  # what would go, without signing anything:
  python3 near-keys.py clean someone.near --keep social.near,wrap.near

  # do it, 50 keys per transaction:
  python3 near-keys.py clean someone.near --keep social.near,wrap.near \
      --key-file ~/.near-credentials/mainnet/someone.near.json --execute
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

RPC_MAINNET = "https://free.rpc.fastnear.com"
RPC_ARCHIVAL = "https://archival-rpc.mainnet.fastnear.com"
CACHE_DIR = os.path.expanduser("~/.near-keys")
PAGE_LIMIT = 100
GAS_TX = 300_000_000_000_000  # 300 Tgas


# --------------------------------------------------------------------------- #
# base58
# --------------------------------------------------------------------------- #
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58)}


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    pad = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body


# --------------------------------------------------------------------------- #
# ed25519 (RFC 8032 reference math, pure Python — ~5 ms per signature)
# --------------------------------------------------------------------------- #
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(b: int, e: int, m: int) -> int:
    r = 1
    b %= m
    while e:
        if e & 1:
            r = r * b % m
        b = b * b % m
        e >>= 1
    return r


def _inv(x: int) -> int:
    return _expmod(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = _expmod(2, (_q - 1) // 4, _q)


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = x * _I % _q
    if x & 1:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_B = (_recover_x(_By), _By)


def _add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    k = _d * x1 * x2 * y1 * y2 % _q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k) % _q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k) % _q
    return (x3, y3)


def _mul(P, e: int):
    R = (0, 1)
    while e:
        if e & 1:
            R = _add(R, P)
        P = _add(P, P)
        e >>= 1
    return R


def _encode_point(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _clamp(sk: bytes) -> int:
    h = _H(sk)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def ed25519_public(sk: bytes) -> bytes:
    return _encode_point(_mul(_B, _clamp(sk)))


def ed25519_sign(msg: bytes, sk: bytes, pk: bytes) -> bytes:
    a = _clamp(sk)
    h = _H(sk)
    prefix = h[32:]
    r = int.from_bytes(_H(prefix + msg), "little") % _l
    R = _encode_point(_mul(_B, r))
    k = int.from_bytes(_H(R + pk + msg), "little") % _l
    S = (r + k * a) % _l
    return R + S.to_bytes(32, "little")


def parse_ed25519_secret(s: str) -> tuple[bytes, bytes]:
    """'ed25519:<b58>' (32-byte seed or 64-byte seed||pub) -> (seed, pubkey)."""
    s = s.strip()
    if not s.startswith("ed25519:") and len(s.split()) >= 12:
        raise SystemExit(
            "that is a seed phrase, not a private key.\n"
            "\n"
            "  This tool cannot derive keys from a seed phrase — it signs with whatever\n"
            "  ed25519 key you hand it. Two ways forward:\n"
            "\n"
            "  1. Let near-cli derive it and write the file this tool reads:\n"
            "     near account import-account using-seed-phrase '<seed phrase>' \\\n"
            "       --seed-phrase-hd-path \"m/44'/397'/0'\" <account> \\\n"
            "       network-config mainnet --check-account-id save-to-legacy-keychain\n"
            "     then: --key-file ~/.near-credentials/mainnet/<account>.json\n"
            "\n"
            "  2. If you already have the key string, it looks like ed25519:<base58>\n"
            "     and goes in NEAR_PRIVATE_KEY or a credentials JSON."
        )
    if not s.startswith("ed25519:"):
        raise SystemExit(
            f"not an ed25519 key: {s[:12]}…\n"
            "  Expected 'ed25519:<base58>'. secp256k1 keys are not supported."
        )
    raw = b58decode(s.split(":", 1)[1])
    if len(raw) == 64:
        seed, pub = raw[:32], raw[32:]
    elif len(raw) == 32:
        seed, pub = raw, ed25519_public(raw)
    else:
        raise SystemExit(f"unexpected ed25519 key length {len(raw)}")
    derived = ed25519_public(seed)
    if derived != pub:
        raise SystemExit("key file is corrupt: derived public key != stored public key")
    return seed, pub


# --------------------------------------------------------------------------- #
# borsh + transaction
# --------------------------------------------------------------------------- #
def _s(text: str) -> bytes:
    b = text.encode()
    return len(b).to_bytes(4, "little") + b


def _pk_bytes(pub_b58: str) -> bytes:
    return b58decode(pub_b58.split(":", 1)[1])


def build_delete_keys_tx_body(signer: str, pub: bytes, key_b58: list[str],
                              nonce: int, block_hash: bytes) -> bytes:
    """Unsigned borsh(Transaction) — inspectable with --dump-tx."""
    tx = b""
    tx += _s(signer)
    tx += b"\x00" + pub                                   # PublicKey::ED25519
    tx += nonce.to_bytes(8, "little")
    tx += _s(signer)                                      # receiver_id == signer
    tx += block_hash
    tx += len(key_b58).to_bytes(4, "little")              # Vec<Action>
    for k in key_b58:
        tx += b"\x06"                                     # Action::DeleteKey (index 6)
        tx += b"\x00" + _pk_bytes(k)                      # PublicKey::ED25519
    return tx


def sign_tx(tx: bytes, seed: bytes, pub: bytes) -> bytes:
    # near hashes sha256(borsh(Transaction)) directly — no SignableMessage
    # variant prefix for the Transaction case (matches @near-js/signers
    # KeyPairSigner.signTransaction).
    sig = ed25519_sign(hashlib.sha256(tx).digest(), seed, pub)
    return tx + b"\x00" + sig                             # Signature::ED25519


def build_delete_keys_tx(signer: str, seed: bytes, pub: bytes,
                         key_b58: list[str], nonce: int, block_hash: bytes) -> bytes:
    return sign_tx(build_delete_keys_tx_body(signer, pub, key_b58, nonce, block_hash), seed, pub)


# --------------------------------------------------------------------------- #
# RPC
# --------------------------------------------------------------------------- #
class Rpc:
    def __init__(self, url: str, retries: int = 4, timeout: int = 40):
        self.url = url
        self.retries = retries
        self.timeout = timeout

    def call(self, method: str, params: dict):
        body = json.dumps({"jsonrpc": "2.0", "id": "near-keys",
                           "method": method, "params": params}).encode()
        last = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(
                    self.url, data=body,
                    headers={"Content-Type": "application/json",
                             "User-Agent": "near-keys/1"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    data = json.loads(r.read())
                if "error" in data:
                    err = data["error"]
                    name = (err.get("cause") or {}).get("name") or err.get("name") or "error"
                    info = err.get("data") or (err.get("cause") or {}).get("info")
                    raise RpcError(name, info, err.get("message"))
                return data["result"]
            except RpcError:
                raise
            except Exception as e:  # noqa: BLE001  network hiccups only
                last = e
                time.sleep(1.5 * (attempt + 1))
        raise SystemExit(f"RPC {self.url} unreachable after {self.retries} tries: {last}")

    # -- query helpers ------------------------------------------------------
    def head(self) -> dict:
        return self.call("block", {"finality": "final"})

    def keys_page(self, account: str, limit=PAGE_LIMIT, after=None, block_id=None) -> dict:
        p = {"request_type": "view_access_key_list", "account_id": account, "limit": limit}
        if after and block_id:
            p["block_id"] = block_id
            p["after_key"] = after
        else:
            p["finality"] = "final"
        return self.call("query", p)

    def view_key(self, account: str, public_key: str) -> dict:
        return self.call("query", {"request_type": "view_access_key",
                                   "finality": "final", "account_id": account,
                                   "public_key": public_key})

    def block_ts(self, height: int) -> int:
        return self.call("block", {"block_id": height})["header"]["timestamp_nanosec"]


class RpcError(Exception):
    def __init__(self, name, info, message=None):
        super().__init__(f"{name}: {info or message}")
        self.name, self.info, self.message = name, info, message


# --------------------------------------------------------------------------- #
# block-height -> timestamp table (cached)
# --------------------------------------------------------------------------- #
def _cache_path(url: str) -> str:
    host = urllib.parse.urlparse(url).netloc.replace(":", "_") or "default"
    return os.path.join(CACHE_DIR, f"blocktimes-{host}.json")


def block_time_table(rpc_archival: Rpc, head_height: int, step=10_000_000,
                     pace=0.7) -> list[tuple[int, int]]:
    """height -> timestamp_nanosec samples, interpolated later. Cached per RPC host
    (testnet and mainnet heights are not comparable, so they must not share a file)."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = _cache_path(rpc_archival.url)
    table: dict[int, int] = {}
    if os.path.exists(cache_path):
        try:
            table = {int(k): int(v) for k, v in json.load(open(cache_path)).items()}
        except Exception:  # noqa: BLE001  corrupt cache = start over
            table = {}
    wanted = sorted({h for h in range(step, head_height, step)}
                    | {head_height - 50_000, head_height})
    missing = [h for h in wanted if 0 < h < head_height and h not in table]
    if not missing:
        return sorted(table.items())

    failures = 0
    for i, h in enumerate(missing, 1):
        got = None
        for attempt in range(3):
            try:
                got = rpc_archival.block_ts(h)
                break
            except (Exception, SystemExit) as e:  # noqa: BLE001
                if "429" in str(e) or "too many" in str(e).lower() or "unreachable" in str(e).lower():
                    time.sleep(3.0 * (attempt + 1))    # rate limit: back off, retry
                else:
                    break
        if got is None:
            failures += 1
            if failures >= 4:
                print("  …archival RPC is rate-limiting; using cached samples only",
                      file=sys.stderr)
                break
            continue
        failures = 0
        table[h] = got
        json.dump({str(k): int(v) for k, v in table.items()}, open(cache_path, "w"))
        if i % 5 == 0:
            print(f"  …block-time table {i}/{len(missing)}", file=sys.stderr)
        time.sleep(pace)
    return sorted(table.items())


def height_to_time(table: list[tuple[int, int]], height: int) -> int | None:
    if not table:
        return None
    height = int(height)
    lo_h, lo_t = int(table[0][0]), int(table[0][1])
    hi_h, hi_t = int(table[-1][0]), int(table[-1][1])
    if height <= lo_h:
        return lo_t
    if height >= hi_h:
        return hi_t
    lo, hi = 0, len(table) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if int(table[mid][0]) <= height:
            lo = mid
        else:
            hi = mid
    h0, t0 = int(table[lo][0]), int(table[lo][1])
    h1, t1 = int(table[hi][0]), int(table[hi][1])
    if h1 == h0:
        return t0
    return int(t0 + (t1 - t0) * (height - h0) / (h1 - h0))


# --------------------------------------------------------------------------- #
# key listing
# --------------------------------------------------------------------------- #
def list_keys(rpc: Rpc, account: str) -> tuple[list[dict], str, int]:
    keys, after, block_hash = [], None, None
    while True:
        page = rpc.keys_page(account, after=after, block_id=block_hash)
        block_hash = block_hash or page["block_hash"]
        keys.extend(page.get("keys", []))
        after = page.get("last_key")
        if not after:
            break
    seen, out = set(), []
    for k in keys:
        if k["public_key"] not in seen:
            seen.add(k["public_key"])
            out.append(k)
    return out, block_hash, page.get("block_height", 0)


def annotate(keys: list[dict], table: list[tuple[int, int]], now_ns: int) -> list[dict]:
    rows = []
    for k in keys:
        ak = k["access_key"]
        perm = ak["permission"]
        nonce = ak["nonce"]
        est_h = nonce // 1_000_000          # near sets nonce ~ block_height * 1e6
        ts = height_to_time(table, est_h)
        rows.append({
            "public_key": k["public_key"],
            "kind": "full" if perm == "FullAccess" else "function_call",
            "receiver_id": None if perm == "FullAccess" else perm["FunctionCall"]["receiver_id"],
            "allowance": None if perm == "FullAccess" else perm["FunctionCall"]["allowance"],
            "method_names": None if perm == "FullAccess" else perm["FunctionCall"]["method_names"],
            "nonce": nonce,
            "last_used_ts": ts,
            "idle_days": None if not ts else round((now_ns - ts) / 86_400e9, 1),
            "scheme": k["public_key"].split(":", 1)[0],
        })
    return rows


def cmd_list(args):
    rpc = Rpc(args.rpc)
    head = rpc.head()
    keys, block_hash, height = list_keys(rpc, args.account)
    print(f"account : {args.account}")
    print(f"snapshot: block {height} {block_hash}")
    print(f"rpc     : {args.rpc}")
    print(f"keys    : {len(keys)} total\n")

    table: list[tuple[int, int]] = []
    if not args.no_ages:
        print("resolving key ages (archival block timestamps, cached)…", file=sys.stderr)
        table = block_time_table(Rpc(args.archival, retries=2, timeout=15), height)
    rows = annotate(keys, table, time.time_ns())

    full = [r for r in rows if r["kind"] == "full"]
    fcs = [r for r in rows if r["kind"] == "function_call"]

    print(f"FULL-ACCESS KEYS ({len(full)}) — these can move funds; do not bulk delete")
    for r in sorted(full, key=lambda r: -(r["idle_days"] or 0)):
        idle = "?" if r["idle_days"] is None else f"{r['idle_days']:.0f}d"
        print(f"  {r['public_key']}  idle {idle}")

    by_recv = defaultdict(list)
    for r in fcs:
        by_recv[r["receiver_id"]].append(r)
    print(f"\nFUNCTION-CALL KEYS: {len(fcs)} across {len(by_recv)} contracts\n")
    w = max([len(k) for k in by_recv] + [16])
    print(f"  {'receiver_id'.ljust(w)}  keys  newest  stale>90d")
    ordered = sorted(by_recv.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for recv, rs in ordered:
        idles = [r["idle_days"] for r in rs if r["idle_days"] is not None]
        newest = f"{min(idles):.0f}d" if idles else "?"
        stale = sum(1 for i in idles if i > 90)
        print(f"  {recv.ljust(w)}  {len(rs):4d}  {newest:>6}  {stale:6d}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            wr.writeheader()
            wr.writerows(rows)
        print(f"\ncsv -> {args.csv}")

    if args.json:
        json.dump({"account": args.account, "block_hash": block_hash,
                   "block_height": height, "keys": rows}, open(args.json, "w"), indent=2)
        print(f"json -> {args.json}")

    # quick triage
    never = sum(1 for r in fcs if r["idle_days"] is None or r["idle_days"] > 365)
    print(f"\nfunction-call keys idle > 1 year: {never} / {len(fcs)}")


# --------------------------------------------------------------------------- #
# deletion
# --------------------------------------------------------------------------- #
def load_signer(args) -> tuple[str, bytes, bytes]:
    path = args.key_file or os.environ.get("NEAR_KEY_FILE")
    secret = os.environ.get("NEAR_PRIVATE_KEY")
    if path:
        data = json.load(open(os.path.expanduser(path)))
        secret = data["private_key"]
        if data.get("account_id") and data["account_id"] != args.account:
            raise SystemExit(f"key file belongs to {data['account_id']}, not {args.account}")
    if not secret:
        raise SystemExit("no signing key: pass --key-file <credentials.json> or set NEAR_PRIVATE_KEY")
    seed, pub = parse_ed25519_secret(secret)
    return "ed25519:" + b58encode(pub), seed, pub


def cmd_clean(args):
    rpc = Rpc(args.rpc)
    keys, block_hash, height = list_keys(rpc, args.account)

    table: list[tuple[int, int]] = []
    if not args.no_ages:
        table = block_time_table(Rpc(args.archival, retries=2, timeout=15), height)
    rows = annotate(keys, table, time.time_ns())

    if args.no_ages and args.stale_days > 0 and not args.all:
        raise SystemExit(
            "--no-ages disables the idle filter: with no block-time data every key looks\n"
            "like it has 0 idle days, so --stale-days would select nothing.\n"
            "Drop --no-ages (the block-time table is cached in ~/.near-keys/) or pass --all."
        )

    keep = {k.strip() for k in (args.keep or "").split(",") if k.strip()}
    full = [r for r in rows if r["kind"] == "full"]
    fcs = [r for r in rows if r["kind"] == "function_call"]

    doomed = [r for r in fcs
              if r["receiver_id"] not in keep
              and r["scheme"] == "ed25519"
              and (args.all or (r["idle_days"] or 0) >= args.stale_days)]
    if args.only:
        only = {k.strip() for k in args.only.split(",") if k.strip()}
        doomed = [r for r in doomed if r["receiver_id"] in only]

    kept_fc = len(fcs) - len(doomed)
    print(f"account      : {args.account} ({len(keys)} keys: {len(full)} full, {len(fcs)} function-call)")
    print(f"keep list    : {', '.join(sorted(keep)) or '(none)'}")
    print(f"stale filter : idle >= {args.stale_days:.0f}d" if not args.all else "stale filter : (all non-kept keys)")
    print(f"to delete    : {len(doomed)} keys")
    print(f"will remain  : {len(full)} full-access + {kept_fc} function-call = {len(full) + kept_fc}")
    if doomed:
        by_recv = defaultdict(list)
        for r in doomed:
            by_recv[r["receiver_id"]].append(r)
        for recv, rs in sorted(by_recv.items(), key=lambda kv: -len(kv[1]))[:25]:
            idle = max((r["idle_days"] or 0) for r in rs)
            print(f"   - {recv:<45} {len(rs):3d} key(s), oldest idle {idle:.0f}d")
        if len(by_recv) > 25:
            print(f"   … and {len(by_recv) - 25} more contracts")

    if args.allow_full_access:
        picked = [r for r in full if r["public_key"] in
                  {p.strip() for p in args.allow_full_access.split(",") if p.strip()}]
        if len(picked) == len(full):
            raise SystemExit("refusing: that would delete every full-access key and brick the account")
        doomed += picked
        print(f"  + {len(picked)} explicitly named full-access key(s)")

    if not doomed:
        print("\nnothing to do.")
        return

    if args.dump_tx:
        head = rpc.head()["header"]
        nonce = head["height"] * 1_000_000 + 1
        first = [r["public_key"] for r in doomed[:args.batch]]
        body = build_delete_keys_tx_body(args.account, b"\x00" * 32, first, nonce,
                                         b58decode(head["hash"]))
        print(f"\nunsigned transaction for batch 1 ({len(first)} DeleteKey actions, "
              f"nonce {nonce}):")
        print(base64.b64encode(body).decode())
        print("decode it with any borsh decoder — it contains only account names, a nonce,")
        print("a block hash and Action::DeleteKey entries. No transfers, no function calls.")

    if not args.execute:
        print("\nDRY RUN — nothing signed. Re-run with --execute to delete.")
        if args.verbose:
            for r in doomed:
                print("   ", r["public_key"], r["receiver_id"])
        return

    signer_pub, seed, pub = load_signer(args)
    vk = rpc.view_key(args.account, signer_pub)["nonce"]
    head_now = rpc.head()["header"]
    nonce = max(vk + 1, head_now["height"] * 1_000_000 + 1)
    batch_size = max(1, args.batch)
    batches = [doomed[i:i + batch_size] for i in range(0, len(doomed), batch_size)]
    print(f"\nsigner       : {signer_pub}")
    print(f"transactions : {len(batches)} (<= {batch_size} DeleteKey actions each)\n")

    ok_keys, failed = [], []
    for i, batch in enumerate(batches, 1):
        keys_b58 = [r["public_key"] for r in batch]
        bh = rpc.head()["header"]
        block_hash_bytes = b58decode(bh["hash"]) if isinstance(bh["hash"], str) else bytes(bh["hash"])
        raw = build_delete_keys_tx(args.account, seed, pub, keys_b58, nonce, block_hash_bytes)
        tx_b64 = base64.b64encode(raw).decode()
        res = rpc.call("broadcast_tx_commit", {"signed_tx_base64": tx_b64})
        status = res["status"]
        if isinstance(status, dict) and "Failure" in status:
            print(f"  [{i}/{len(batches)}] FAILED  {res['transaction']['hash']}  {json.dumps(status['Failure'])[:300]}")
            failed.extend(keys_b58)
        else:
            print(f"  [{i}/{len(batches)}] ok  {res['transaction']['hash']}  {len(keys_b58)} keys deleted")
            ok_keys.extend(keys_b58)
        nonce += 1
        time.sleep(args.pause)

    # ---- verify ----
    # One paginated re-list beats one request per key: 282 sequential view_access_key
    # calls take minutes and look like a hang.
    print("\nverifying… (paginated re-list)")
    remaining, _, rem_h = list_keys(rpc, args.account)
    present = {k["public_key"] for k in remaining}
    still_there = [k for k in ok_keys if k in present]
    print(f"deleted : {len(ok_keys) - len(still_there)}")
    print(f"failures: {len(failed) + len(still_there)}")
    print(f"now     : {len(remaining)} keys at block {rem_h}")
    if still_there:
        print("still present (re-run clean for these):")
        for k in still_there:
            print("   ", k)
    if failed:
        print("failed batches — nothing was deleted for:")
        for k in failed[:20]:
            print("   ", k)


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("account")
        p.add_argument("--rpc", default=RPC_MAINNET)
        p.add_argument("--archival", default=RPC_ARCHIVAL)
        p.add_argument("--no-ages", action="store_true", help="skip block-time resolution")

    lp = sub.add_parser("list", help="read-only report")
    common(lp)
    lp.add_argument("--csv")
    lp.add_argument("--json")
    lp.set_defaults(func=cmd_list)

    cp = sub.add_parser("clean", help="delete stale function-call keys")
    common(cp)
    cp.add_argument("--keep", help="comma-separated receiver_ids to preserve")
    cp.add_argument("--only", help="restrict deletion to these receiver_ids")
    cp.add_argument("--stale-days", type=float, default=0.0,
                    help="only delete keys idle at least this long (default 0 = all non-kept)")
    cp.add_argument("--all", action="store_true", help="ignore the idle filter")
    cp.add_argument("--allow-full-access", help="comma-separated full-access keys to delete (dangerous)")
    cp.add_argument("--batch", type=int, default=50, help="DeleteKey actions per transaction")
    cp.add_argument("--pause", type=float, default=1.5, help="seconds between transactions")
    cp.add_argument("--key-file", help="NEAR credentials JSON with a full-access private_key")
    cp.add_argument("--execute", action="store_true", help="actually sign and send")
    cp.add_argument("--dump-tx", action="store_true",
                    help="print the unsigned borsh transaction for the first batch and exit")
    cp.add_argument("--verbose", action="store_true")
    cp.set_defaults(func=cmd_clean)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
