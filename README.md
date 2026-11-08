# too-many-keys

Audit and prune the access keys on a NEAR account that has drifted past the RPC's
100-key limit — the state that breaks near.social logins and any wallet that resolves a
full-access key by listing keys.

## What this tool will never do

Worth stating plainly, because "a script that handles account keys" should make you
suspicious:

- **It never asks for a seed phrase**, and there is no code path that accepts one. It reads a
  credentials JSON in the format `near-cli` already writes, and refuses the file if the
  private key does not derive the stored public key.
- **It makes no network calls except to the RPC endpoint you pass** (`--rpc`, default
  `https://free.rpc.fastnear.com`). No telemetry, no analytics, no "check for updates".
- **It can only delete.** The transaction it builds contains `Action::DeleteKey` entries and
  nothing else — no transfers, no function calls, no `AddKey`. You don't have to take that
  on faith: `--dump-tx` prints the unsigned borsh body, and any borsh decoder will show you
  exactly what it holds.
- **It cannot be pointed at someone else's account.** `DeleteKey` acts on the signer's own
  account, so the receiver is always the signer.

If you want to check any of this before running it: the tool has no imports beyond
`hashlib`, `json`, `urllib`, `argparse` and friends.

Two subcommands, one file, standard library only:


```
near-keys.py list  <account>     # read-only report
near-keys.py clean <account>     # delete, dry-run unless --execute
```

No pip, no npm, no near-cli dependency. Python 3.9+.

---

## Why this exists

Since nearcore 2.14.0 an **unpaginated** `view_access_key_list` is rejected when an account
holds more than the node's `view_access_keys_limit` (100 by default):

```
[-32000] Server error: Account <account> has more than 100 access keys;
use a paginated view_access_key_list request
```

Many clients still call it without `limit`/`after_key`, so a long-lived account simply
stops working in them. The account is fine — its key list is just too long to serve in one
response.

Where that shows up today:

- near/near-api-js#2028 — the SDK's generated RPC types predate `after_key`/`limit`, so
  `viewAccessKeyList()` cannot express the paginated request at all.
- NearSocial/viewer#254 — near.social's function-call-key path lists every key before using
  the one it already has locally, and fails hard instead of falling back to the wallet.

This tool does the other half: it reads the list correctly and lets you delete the dead
entries. Accounts typically accumulate one function-call key per app, per login, forever.

## Quickstart

```bash
python3 near-keys.py list someone.near --csv keys.csv     # no key needed
python3 near-keys.py clean someone.near --keep myapp.near  # dry run
python3 near-keys.py clean someone.near --keep myapp.near \
    --stale-days 365 --dump-tx                                  # inspect the unsigned tx
python3 near-keys.py clean someone.near --keep myapp.near \
    --stale-days 365 --key-file ~/.near-credentials/mainnet/someone.near.json --execute
```

`list` pages with `limit`/`after_key`, pins every page to the first page's `block_hash` so
the snapshot is consistent, groups keys by the contract each one may call, and estimates
last use from the block height encoded in each key's nonce (real block timestamps come from
the archival RPC and are cached in `~/.near-keys/`).

`clean` deletes function-call keys in batches — up to 50 `DeleteKey` actions per
transaction, so 280 keys is 6 transactions rather than 280.

## Getting a signer key

`clean --execute` needs a **full-access** key for the account. Standard credentials JSON:

```json
{"account_id":"someone.near","public_key":"ed25519:…","private_key":"ed25519:…"}
```

near-cli-rs can put it there for you (this is the format it already uses):

```bash
near account import-account using-private-key <ed25519:…> someone.near \
  network-config mainnet
```

The script refuses a file whose seed does not derive the stored public key, so a corrupted
or mismatched file fails before anything is signed. Do not commit key files — `.gitignore`
already excludes the usual shapes.

## Safety model

- **Dry run is the default.** Nothing is signed without `--execute`.
- **Full-access keys are never deleted** unless you name them individually in
  `--allow-full-access`, and the tool refuses if that would delete *all* of them and brick
  the account.
- Non-ed25519 keys (secp256k1) are skipped — the local signer only supports ed25519.
- After sending, the account is re-listed (paginated) and every deleted key is checked
  against that fresh list. One re-list, not one request per key — 282 sequential
  `view_access_key` calls take minutes and look like a hang.
- Deleting a function-call key logs an app out; it cannot move funds. That is why the keep
  list is usually just your own contracts.

## What has been verified

- ed25519 and base58 pass the RFC 8032 test vectors.
- Transaction bytes and signatures are **byte-identical** to `@near-js/signers`
  `KeyPairSigner.signTransaction` for the same inputs.
- Multi-action `DeleteKey` batches executed on testnet, verified gone afterwards.
- Read-only audits against mainnet accounts holding 293 keys (3 pages at `limit=100`).

- **Full prune run on mainnet**: a 293-key account cleaned to 11 keys — 282 deletions in 6
  transactions (50/50/50/50/50/32), every transaction confirmed, then re-listed to verify.
  The account moved from "unusable in any non-paginating client" to working again, and
  logging into near.social with it worked immediately afterwards.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Offline, no network, no keys: RFC 8032 vectors, base58 round-trips, the transaction body
(parsed back out and asserted to be exactly N × `DeleteKey` with nothing trailing), and the
signer-input refusals. CI runs them on Python 3.9 and 3.12.

## When to reach for this instead of near-cli-rs

If you want to delete one key you know by name, near-cli-rs does it:
`near account delete-keys <account> public-keys <pk> network-config mainnet … send`.

This tool exists for the case above the limit, where listing keys in the CLI fails before you
can see what to delete, and where you want ages and receiver grouping to decide.

## Implementation notes

Things that cost real debugging time, in case you fork this:

1. A transaction is signed over `sha256(borsh(tx))` — *not* over a borsh enum with a `u32`
   variant prefix. The prefixed form is rejected with `InvalidTransaction:
   InvalidSignature` even though the transaction bytes are identical.
2. `Action::DeleteKey` is enum variant 6 (`AddKey` is 5 — an off-by-one silently *adds* a
   key).
3. `block_hash` expires after ~2 epochs (24h); fetch a fresh head per batch.
4. The nonce must satisfy both `> access_key.nonce` and `>= head_height * 1e6`.
5. Pagination params are `limit` + `after_key`; `after` and an empty string are ignored.
6. `archival-rpc.mainnet.near.org` rate-limits hard (HTTP 429);
   `archival-rpc.mainnet.fastnear.com` works.

## License

MIT.
