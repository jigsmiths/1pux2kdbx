# 1pux2kdbx

Convert a 1Password `.1pux` export to a KeePass `.kdbx` file with stable UUIDs.

KeePassXC's built-in 1PUX importer assigns a random UUID to every entry on each
import, so re-importing duplicates everything. This tool derives each entry and
group UUID from the 1Password vault and item IDs, and keeps 1Password's created
and updated timestamps. That lets `keepassxc-cli merge` reconcile a new export
with an earlier one: new items are added, changed items are updated, unchanged
items are left alone.

## Install

```sh
brew install jigsmiths/tap/1pux2kdbx
```

or

```sh
go install github.com/jigsmiths/1pux2kdbx/cmd/1pux2kdbx@latest
```

## Use

One-off conversion:

```sh
1pux2kdbx -in export.1pux -out backup.kdbx
```

Ongoing sync into a long-lived backup (dry-run, confirm, merge), from a clone
of this repo:

```sh
just sync ~/Downloads/1PasswordExport-*.1pux ~/Passwords/backup.kdbx
```

The password is read from `KDBX_PASSWORD` or prompted. Point KeePassium at the
backup file (for example in iCloud Drive) and it picks up each merge.

## What is converted

- Vault to group, item to entry, with 1Password timestamps.
- Username, password, URL, extra URLs, notes, tags, favourite and archived tags.
- Section fields as custom attributes, concealed fields protected.
- TOTP as the `otp` attribute KeePassXC uses.
- Documents and file fields as attachments.
- SSH keys: private key attached as `id_<type>`, public key and fingerprint as
  attributes, so KeePassXC's SSH agent can use them.

Trashed items are skipped. Custom icons are not imported.

The kdbx uses Argon2d with 64 MiB and 10 iterations, matching KeePassXC's defaults.
All timestamps come from the export, so converting the same export twice gives
entries that merge without conflict warnings.

## Develop

```sh
just setup   # git hooks
just check   # gofmt, golangci-lint, tests
```

The end-to-end test runs the real `keepassxc-cli merge` and skips if it is not
installed. `KEEPASSXC_CLI` defaults to the macOS app bundle binary.

## Limits

- Deletions in 1Password are not propagated by merge. Remove them by hand.
- An item moved between vaults gets a new UUID and shows up as a new entry.
- The 1PUX export is unencrypted. Delete it after syncing.
