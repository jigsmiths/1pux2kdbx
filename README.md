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

Merges never delete. Instead, `just sync` passes the backup as `-previous`, and
entries whose items are gone from the export are tagged `Deleted in 1Password`.
Entries you created in KeePassXC, entries in the recycle bin and entries edited
after the export are left alone. Restoring the item in 1Password drops the tag.

## What is converted

- Vault to group, item to entry, with 1Password timestamps.
- Username, password, URL, extra URLs, notes, tags, favourite and archived tags.
- Password history as entry history.
- Section fields as custom attributes. Concealed fields and card numbers are
  protected; repeated field names get a `_2`, `_3` suffix.
- TOTP as the `otp` attribute KeePassXC uses.
- "Sign in with" links as a KeePassXC reference to the linked login.
- Documents and file fields as attachments.
- SSH keys: private key attached as `id_<type>`, public key and fingerprint as
  attributes. ed25519 keys are converted to OpenSSH format (the original is kept
  as `id_ed25519.pkcs8`). Each key is set up for KeePassXC's SSH agent: added
  when the database opens, removed when it closes.

1Password leaves trashed items out of its exports. Custom icons are not imported.

The kdbx uses Argon2d with 64 MiB and 10 iterations, matching KeePassXC's defaults.
All timestamps come from the export, so converting the same export twice gives
entries that merge without conflict warnings.

## Develop

```sh
just setup   # git hooks
just check   # gofmt, golangci-lint, tests
```

The end-to-end tests run the real `keepassxc-cli merge` and skip if it is not
installed. `KEEPASSXC_CLI` defaults to the macOS app bundle binary.

`testdata/spec` is a fake export following 1Password's 1PUX docs; after an
intended output change, run `go test ./cmd/1pux2kdbx -run TestGolden -update`
and review the diff. To check against a real export without committing it:

```sh
ONEPUX_FIXTURE=~/Downloads/1PasswordExport.1pux go test ./cmd/1pux2kdbx -run TestRealExport -v
```

## Limits

- Items deleted in 1Password are only tagged. Remove them by hand.
- An item moved between vaults gets a new UUID and shows up as a new entry; the
  old one is tagged deleted.
- The 1PUX export is unencrypted. Delete it after syncing.
