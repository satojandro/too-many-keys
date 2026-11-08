# Security

This tool builds and signs NEAR transactions that delete access keys. That is a
destructive operation on a live account, so here is the threat model, up front.

## What it can do

- Delete function-call access keys from the account you sign for.
- Delete full-access keys **only** if you name each one explicitly in `--allow-full-access`,
  and it refuses if that would leave the account with none.
- Read public chain state (access key lists, block timestamps).

## What it cannot do

- Move funds. There is no `Transfer`, `FunctionCall`, `Stake` or `AddKey` in any transaction
  it builds — only `Action::DeleteKey`. Verify with `--dump-tx`.
- Touch another account. `DeleteKey` applies to the signer, so `receiver_id` is always the
  signer.
- Exfiltrate anything. The only network destination is the RPC URL you pass with `--rpc`.
  There is no telemetry and no update check.
- Accept a seed phrase. The signer input is a credentials JSON file; the tool derives the
  public key from the seed and aborts if it doesn't match the stored one.

## Verifying before you run it

1. `python3 near-keys.py clean <account> --keep <contracts>` — dry run, prints the plan and
   signs nothing.
2. Add `--dump-tx` — prints the unsigned borsh for the first batch. Decode it; you should see
   account IDs, a nonce, a block hash, and `DeleteKey` actions only.
3. Read the file. It is one script with no dependencies beyond the Python standard library.

## Handling your key

Prefer letting `near-cli` hold it (`near account import-account …`), which writes
`~/.near-credentials/<network>/<account>.json` — the format this tool reads. If you keep
credentials elsewhere, pass the path with `--key-file` and do not commit it; `.gitignore`
excludes the common shapes.

Never paste a private key into a shell history you don't control, an issue, or a chat.

## Reporting a problem

Open an issue with the command you ran (redact the account if you prefer), what you expected
and what happened. If it is something that could lead to loss of keys or funds, email
`avbetancourt@protonmail.com` instead of filing publicly.
