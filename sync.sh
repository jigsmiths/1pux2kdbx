#!/usr/bin/env bash
# Convert a fresh 1Password export and merge it into the long-lived backup kdbx.
#
#   ./sync.sh ~/Downloads/1PasswordExport-*.1pux ~/Passwords/backup.kdbx
#
# The first run (no backup yet) just writes the converted file as the backup.
# Later runs show a dry-run merge, ask for confirmation, then merge.
set -euo pipefail

in=${1:?usage: sync.sh <export.1pux> <backup.kdbx>}
backup=${2:?usage: sync.sh <export.1pux> <backup.kdbx>}
cli=${KEEPASSXC_CLI:-/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [[ -z "${KDBX_PASSWORD:-}" ]]; then
  read -rsp "kdbx password: " KDBX_PASSWORD; echo
  export KDBX_PASSWORD
fi

fresh="$tmp/fresh.kdbx"
1pux2kdbx -in "$in" -out "$fresh"

if [[ ! -f "$backup" ]]; then
  mv "$fresh" "$backup"
  echo "created $backup"
  exit 0
fi

cp "$backup" "$backup.bak"
# No -q here: it also hides the list of changes we want to review.
echo "$KDBX_PASSWORD" | "$cli" merge -s --dry-run "$backup" "$fresh" 2>&1 | grep -v "^Enter password"
read -rp "apply merge? [y/N] " ok
[[ $ok == y ]] || exit 1
echo "$KDBX_PASSWORD" | "$cli" merge -q -s "$backup" "$fresh"
echo "merged into $backup (previous copy at $backup.bak)"
