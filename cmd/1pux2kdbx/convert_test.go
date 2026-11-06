package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	kp "github.com/tobischo/gokeepasslib/v3"
)

const testPassword = "correct horse battery staple"

// Test data is written as plain maps so each case reads like the real export.

func login(id, title, user, pass string, updated int64) map[string]any {
	return map[string]any{
		"uuid": id, "createdAt": 1700000000, "updatedAt": updated, "state": "active",
		"overview": map[string]any{"title": title, "url": "https://" + id + ".example"},
		"details": map[string]any{
			"loginFields": []any{
				map[string]any{"designation": "username", "value": user},
				map[string]any{"designation": "password", "value": pass},
			},
		},
	}
}

func withSection(it map[string]any, fields ...map[string]any) map[string]any {
	d := it["details"].(map[string]any)
	d["sections"] = []any{map[string]any{"title": "Extra", "fields": fields}}
	return it
}

func fieldOf(title, kind string, value any) map[string]any {
	return map[string]any{"title": title, "value": map[string]any{kind: value}}
}

func vaultOf(id, name string, items ...map[string]any) map[string]any {
	return map[string]any{"attrs": map[string]any{"uuid": id, "name": name}, "items": items}
}

// write1pux builds a .1pux zip from vaults plus extra files under files/.
func write1pux(t *testing.T, path string, files map[string]string, vaults ...map[string]any) {
	t.Helper()
	write1puxAt(t, path, 1750000000, files, vaults...)
}

// write1puxAt is write1pux for an export taken at the given Unix time.
func write1puxAt(t *testing.T, path string, exported int64, files map[string]string, vaults ...map[string]any) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"accounts": []any{map[string]any{"vaults": vaults}}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	add := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	add("export.data", string(data))
	add("export.attributes", fmt.Sprintf(`{"version":3,"description":"1Password Unencrypted Export","createdAt":%d}`, exported))
	for name, body := range files {
		add("files/"+name, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func convertT(t *testing.T, in, out string) stats {
	t.Helper()
	return convertPrev(t, in, out, "")
}

// convertPrev converts with an existing backup to tag deleted items against.
func convertPrev(t *testing.T, in, out, previous string) stats {
	t.Helper()
	s, err := convert(in, out, "Backup", testPassword, previous)
	if err != nil {
		t.Fatalf("convert %s: %v", in, err)
	}
	return s
}

// open decodes a kdbx and indexes entries by "<group>/<title>".
func open(t *testing.T, path string) (*kp.Database, map[string]kp.Entry) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	db := kp.NewDatabase()
	db.Credentials = kp.NewPasswordCredentials(testPassword)
	if err := kp.NewDecoder(f).Decode(db); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	entries := map[string]kp.Entry{}
	for _, g := range db.Content.Root.Groups[0].Groups {
		for _, e := range g.Entries {
			key := g.Name + "/" + e.GetTitle()
			if _, dup := entries[key]; dup {
				t.Errorf("duplicate entry %s", key)
			}
			// KeePassXC refuses to open a database with repeated attribute keys.
			seen := map[string]bool{}
			for _, v := range e.Values {
				if seen[v.Key] {
					t.Errorf("%s: duplicate attribute %q", key, v.Key)
				}
				seen[v.Key] = true
			}
			entries[key] = e
		}
	}
	return db, entries
}

func attachment(t *testing.T, db *kp.Database, e kp.Entry, name string) string {
	t.Helper()
	for _, ref := range e.Binaries {
		if ref.Name == name {
			b, err := db.FindBinary(ref.Value.ID).GetContentBytes()
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
	t.Errorf("%s: no attachment %q", e.GetTitle(), name)
	return ""
}

// baseExport is the first export: two vaults, and an item UUID shared across
// vaults to prove vault scoping.
func baseExport(t *testing.T, path, bankPass string, bankUpdated int64, extra ...map[string]any) {
	ssh := map[string]any{
		"uuid": "sshkey", "createdAt": 1700000000, "updatedAt": 1700000000, "state": "active",
		"overview": map[string]any{"title": "Laptop key"},
		"details": map[string]any{"sections": []any{map[string]any{"fields": []any{
			fieldOf("private key", "sshKey", map[string]any{
				"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
				"metadata":   map[string]any{"keyType": "ed25519", "publicKey": "ssh-ed25519 AAAA", "fingerprint": "SHA256:xyz"},
			}),
		}}}},
	}
	doc := map[string]any{
		"uuid": "doc", "createdAt": 1700000000, "updatedAt": 1700000000, "state": "active",
		"overview": map[string]any{"title": "Passport scan"},
		"details":  map[string]any{"documentAttributes": map[string]any{"fileName": "passport.pdf", "documentId": "d1"}},
	}
	mail := withSection(login("mail", "Mail", "me@example.com", "old-pass", 1700000000),
		fieldOf("one-time password", "totp", "JBSWY3DPEHPK3PXP"),
		fieldOf("recovery code", "concealed", "r-123"),
	)
	bank := login("bank", "Bank", "me", bankPass, bankUpdated)
	if bankPass != "bank-pass" {
		// 1Password records the replaced password in the item's history.
		bank["details"].(map[string]any)["passwordHistory"] = []any{
			map[string]any{"value": "bank-pass", "time": bankUpdated},
		}
	}
	personal := append([]map[string]any{mail, bank, ssh, doc}, extra...)
	write1pux(t, path, map[string]string{"d1__passport.pdf": "PDFDATA"},
		vaultOf("vpersonal", "Personal", personal...),
		vaultOf("vwork", "Work", login("mail", "Work mail", "me@work.example", "work-pass", 1700000000)),
	)
}

func TestFieldMapping(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	baseExport(t, in, "bank-pass", 1700000000, map[string]any{
		"uuid": "gone", "state": "trashed", "overview": map[string]any{"title": "Trashed"},
	})

	s := convertT(t, in, out)
	if s.entries != 5 || s.skipped != 1 || s.attachments != 2 {
		t.Errorf("stats = %+v, want 5 entries, 1 skipped, 2 attachments", s)
	}

	db, es := open(t, out)
	mail := es["Personal/Mail"]
	for key, want := range map[string]string{
		"UserName":            "me@example.com",
		"Password":            "old-pass",
		"URL":                 "https://mail.example",
		"Extra_recovery code": "r-123",
		"otp":                 "otpauth://totp/Mail:me@example.com?secret=JBSWY3DPEHPK3PXP",
	} {
		if got := mail.GetContent(key); got != want {
			t.Errorf("Mail %s = %q, want %q", key, got, want)
		}
	}
	if got := mail.Times.LastModificationTime.Time.Unix(); got != 1700000000 {
		t.Errorf("Mail mtime = %d, want 1700000000", got)
	}

	ssh := es["Personal/Laptop key"]
	if got := attachment(t, db, ssh, "id_ed25519"); !strings.Contains(got, "OPENSSH PRIVATE KEY") {
		t.Errorf("ssh private key attachment = %q", got)
	}
	if got := ssh.GetContent("SSH Public Key"); got != "ssh-ed25519 AAAA" {
		t.Errorf("ssh public key = %q", got)
	}
	if got := attachment(t, db, es["Personal/Passport scan"], "passport.pdf"); got != "PDFDATA" {
		t.Errorf("document attachment = %q", got)
	}
	if mail.UUID == es["Work/Work mail"].UUID {
		t.Error("same item UUID in two vaults produced the same entry UUID")
	}
	if _, ok := es["Personal/Trashed"]; ok {
		t.Error("trashed item was converted")
	}
}

func TestStableUUIDs(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.1pux")
	baseExport(t, in, "bank-pass", 1700000000)
	convertT(t, in, filepath.Join(dir, "1.kdbx"))
	convertT(t, in, filepath.Join(dir, "2.kdbx"))

	_, first := open(t, filepath.Join(dir, "1.kdbx"))
	_, second := open(t, filepath.Join(dir, "2.kdbx"))
	for k, e := range first {
		if second[k].UUID != e.UUID {
			t.Errorf("%s: UUID changed between conversions", k)
		}
	}
}

// TestMergeEndToEnd converts two exports and merges them with the real
// keepassxc-cli, as sync.sh does.
func TestMergeEndToEnd(t *testing.T) {
	cli := os.Getenv("KEEPASSXC_CLI")
	if cli == "" {
		cli = "keepassxc-cli"
	}
	if _, err := exec.LookPath(cli); err != nil {
		t.Skip("keepassxc-cli not found")
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "b.1pux")
	backup, fresh := filepath.Join(dir, "backup.kdbx"), filepath.Join(dir, "fresh.kdbx")

	// Export A becomes the backup.
	baseExport(t, a, "bank-pass", 1700000000)
	convertT(t, a, backup)
	_, before := open(t, backup)

	// Export B: Bank password changed later, a new item added, rest unchanged.
	baseExport(t, b, "new-bank-pass", 1700000900, login("shop", "Shop", "me", "shop-pass", 1700000500))
	convertT(t, b, fresh)

	merge := func() {
		cmd := exec.Command(cli, "merge", "-q", "-s", backup, fresh)
		cmd.Stdin = strings.NewReader(testPassword + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("merge: %v\n%s", err, out)
		}
		// Unchanged entries must compare equal, or every sync drowns real
		// conflicts in noise.
		if strings.Contains(string(out), "conflicting changes") {
			t.Errorf("merge reported conflicts:\n%s", out)
		}
	}
	merge()
	_, after := open(t, backup)

	if len(after) != len(before)+1 {
		t.Errorf("entries after merge = %d, want %d", len(after), len(before)+1)
	}
	bank := after["Personal/Bank"]
	if got := bank.GetPassword(); got != "new-bank-pass" {
		t.Errorf("Bank password = %q, want new-bank-pass", got)
	}
	if len(bank.Histories) == 0 || len(bank.Histories[0].Entries) == 0 {
		t.Error("Bank has no history entry for the old password")
	}
	if _, ok := after["Personal/Shop"]; !ok {
		t.Error("new item Shop was not added")
	}
	for k, e := range before {
		if after[k].UUID != e.UUID {
			t.Errorf("%s: UUID changed by merge", k)
		}
	}

	// Merging the same export again must change nothing.
	merge()
	_, again := open(t, backup)
	if len(again) != len(after) {
		t.Errorf("second merge changed entry count %d -> %d", len(after), len(again))
	}
	snaps := func(es map[string]kp.Entry) []string {
		var out []string
		for _, h := range es["Personal/Bank"].Histories {
			for _, s := range h.Entries {
				out = append(out, fmt.Sprintf("%s@%d", s.GetPassword(), s.Times.LastModificationTime.Time.Unix()))
			}
		}
		return out
	}
	t.Logf("Bank history after merges: %v", snaps(again))
	if a, b := snaps(after), snaps(again); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("second merge changed Bank history %v -> %v", a, b)
	}
}

// TestSyncRecipe drives `just sync` the way a user does: first run creates the
// backup, a declined merge leaves it alone, an accepted merge applies it.
func TestSyncRecipe(t *testing.T) {
	just, err := exec.LookPath("just")
	if err != nil {
		t.Skip("just not found")
	}
	cli := os.Getenv("KEEPASSXC_CLI")
	if cli == "" {
		cli = "keepassxc-cli"
	}
	cliPath, err := exec.LookPath(cli)
	if err != nil {
		t.Skip("keepassxc-cli not found")
	}

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "b.1pux")
	backup := filepath.Join(dir, "backup.kdbx")
	baseExport(t, a, "bank-pass", 1700000000)
	baseExport(t, b, "new-bank-pass", 1700000900, login("shop", "Shop", "me", "shop-pass", 1700000500))

	sync := func(export, answer string) (string, error) {
		cmd := exec.Command(just, "sync", export, backup)
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "KDBX_PASSWORD="+testPassword, "KEEPASSXC_CLI="+cliPath)
		cmd.Stdin = strings.NewReader(answer)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := sync(a, ""); err != nil || !strings.Contains(out, "created") {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	if _, err := os.Stat(backup + ".bak"); err == nil {
		t.Error("first run left a .bak file")
	}
	_, first := open(t, backup)
	original, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}

	if out, err := sync(b, "n\n"); err == nil {
		t.Fatalf("declined merge exited 0\n%s", out)
	}
	if now, err := os.ReadFile(backup); err != nil || string(now) != string(original) {
		t.Error("declined merge changed the backup")
	}

	out, err := sync(b, "y\n")
	if err != nil || !strings.Contains(out, "merged into") {
		t.Fatalf("accepted merge: %v\n%s", err, out)
	}
	_, merged := open(t, backup)
	if len(merged) != len(first)+1 {
		t.Errorf("entries after merge = %d, want %d", len(merged), len(first)+1)
	}
	bank := merged["Personal/Bank"]
	if got := bank.GetPassword(); got != "new-bank-pass" {
		t.Errorf("Bank password = %q, want new-bank-pass", got)
	}
	if prev, err := os.ReadFile(backup + ".bak"); err != nil || string(prev) != string(original) {
		t.Error(".bak is not the pre-merge backup")
	}
}
