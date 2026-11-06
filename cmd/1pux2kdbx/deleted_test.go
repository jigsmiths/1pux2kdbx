package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kp "github.com/tobischo/gokeepasslib/v3"
)

// kpcli runs keepassxc-cli with the test password on stdin.
func kpcli(t *testing.T, args ...string) string {
	t.Helper()
	cli := os.Getenv("KEEPASSXC_CLI")
	if cli == "" {
		cli = "keepassxc-cli"
	}
	if _, err := exec.LookPath(cli); err != nil {
		t.Skip("keepassxc-cli not found")
	}
	cmd := exec.Command(cli, args...)
	cmd.Stdin = strings.NewReader(testPassword + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keepassxc-cli %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func tagged(e kp.Entry) bool { return hasTag(e.Tags, deletedTag) }

// TestDeletedItems follows items deleted in 1Password through several syncs:
// tagged where they sit, stable on the next sync, untagged once restored.
func TestDeletedItems(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "b.1pux"), filepath.Join(dir, "c.1pux")
	backup, fresh := filepath.Join(dir, "backup.kdbx"), filepath.Join(dir, "fresh.kdbx")

	const keyFile = "KEYFILE contents long enough to read back"
	mail := login("mail", "Mail", "me", "m", 1700000000)
	bank := login("bank", "Bank", "me", "bank-pass", 1700000900)
	bank["details"].(map[string]any)["passwordHistory"] = []any{
		map[string]any{"value": "old-bank-pass", "time": 1700000000},
	}
	key := login("key", "Server key", "root", "k", 1700000000)
	key["details"].(map[string]any)["documentAttributes"] = map[string]any{"fileName": "key.pem", "documentId": "d1"}
	work := vaultOf("vwork", "Work", login("mail", "Work mail", "me", "w", 1700000000))

	write1puxAt(t, a, 1750000000, map[string]string{"d1__key.pem": keyFile},
		vaultOf("vpersonal", "Personal", mail, bank, key), work)
	convertT(t, a, backup)

	// The user adds an entry of their own and files the key under SSH.
	kpcli(t, "add", backup, "Personal/Mine")
	kpcli(t, "mkdir", backup, "SSH")
	kpcli(t, "mv", backup, "Personal/Server key", "SSH")

	// Bank and the key are then deleted in 1Password.
	now := time.Now().Unix()
	write1puxAt(t, b, now+3600, nil, vaultOf("vpersonal", "Personal", mail), work)
	if s := convertPrev(t, b, fresh, backup); s.deleted != 2 {
		t.Errorf("deleted = %d, want 2", s.deleted)
	}
	merge := func() string { return kpcli(t, "merge", "-s", backup, fresh) }
	merge()

	db, es := open(t, backup)
	for _, k := range []string{"Personal/Bank", "SSH/Server key"} {
		if !tagged(es[k]) {
			t.Errorf("%s is not tagged %q (tags %q)", k, deletedTag, es[k].Tags)
		}
	}
	for _, k := range []string{"Personal/Mail", "Personal/Mine", "Work/Work mail"} {
		if _, ok := es[k]; !ok || tagged(es[k]) {
			t.Errorf("%s: missing or wrongly tagged", k)
		}
	}
	if _, ok := es["Personal/Server key"]; ok {
		t.Error("tagging moved the key back out of SSH")
	}
	bankEntry := es["Personal/Bank"]
	if got := bankEntry.GetPassword(); got != "bank-pass" {
		t.Errorf("tagged Bank password = %q, want bank-pass", got)
	}
	if got := attachment(t, db, es["SSH/Server key"], "key.pem"); got != keyFile {
		t.Errorf("tagged key attachment = %q", got)
	}
	var old []string
	for _, h := range es["Personal/Bank"].Histories {
		for _, s := range h.Entries {
			old = append(old, s.GetPassword())
		}
	}
	if !strings.Contains(strings.Join(old, " "), "old-bank-pass") {
		t.Errorf("tagged Bank lost its password history: %v", old)
	}

	// The next sync, with both items still gone, changes nothing.
	convertPrev(t, b, fresh, backup)
	if out := merge(); !strings.Contains(out, "not modified") {
		t.Errorf("second sync changed the backup:\n%s", out)
	}

	// Bank is restored in 1Password, unchanged.
	write1puxAt(t, c, now+7200, nil, vaultOf("vpersonal", "Personal", mail, bank), work)
	if s := convertPrev(t, c, fresh, backup); s.deleted != 1 {
		t.Errorf("deleted after restore = %d, want 1", s.deleted)
	}
	merge()
	_, es = open(t, backup)
	if tagged(es["Personal/Bank"]) {
		t.Error("restored Bank is still tagged")
	}
	if !tagged(es["SSH/Server key"]) {
		t.Error("key lost its tag when Bank was restored")
	}
	convertPrev(t, c, fresh, backup)
	if out := merge(); !strings.Contains(out, "not modified") {
		t.Errorf("sync after restore is not stable:\n%s", out)
	}
}

// An entry edited after the export was taken is left alone: the export
// cannot know about the edit, so it is no evidence of deletion.
func TestDeletedSkipsLaterEdits(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "b.1pux")
	backup, fresh := filepath.Join(dir, "backup.kdbx"), filepath.Join(dir, "fresh.kdbx")
	mail := login("mail", "Mail", "me", "m", 1700000000)
	write1puxAt(t, a, 1750000000, nil, vaultOf("v", "Personal", mail, login("bank", "Bank", "me", "p", 1700000000)))
	convertT(t, a, backup)
	kpcli(t, "edit", "-u", "edited", backup, "Personal/Bank")

	write1puxAt(t, b, 1750000100, nil, vaultOf("v", "Personal", mail))
	if s := convertPrev(t, b, fresh, backup); s.deleted != 0 {
		t.Errorf("deleted = %d, want 0", s.deleted)
	}
	kpcli(t, "merge", "-s", backup, fresh)
	_, es := open(t, backup)
	if e := es["Personal/Bank"]; tagged(e) || e.GetContent("UserName") != "edited" {
		t.Errorf("edited Bank: tags %q, user %q", e.Tags, e.GetContent("UserName"))
	}
}
