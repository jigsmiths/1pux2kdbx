package main

import (
	"archive/zip"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// itemWith builds a bare active item whose extra fields live in section "Extra".
func itemWith(id, title string, fields ...map[string]any) map[string]any {
	it := map[string]any{
		"uuid": id, "createdAt": 1700000000, "updatedAt": 1700000000, "state": "active",
		"overview": map[string]any{"title": title},
		"details":  map[string]any{},
	}
	if len(fields) > 0 {
		withSection(it, fields...)
	}
	return it
}

func convertItems(t *testing.T, items ...map[string]any) (map[string]string, stats) {
	t.Helper()
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	write1pux(t, in, nil, vaultOf("v", "V", items...))
	s := convertT(t, in, out)
	_, es := open(t, out)
	res := map[string]string{}
	for k, e := range es {
		for _, v := range e.Values {
			res[k+"|"+v.Key] = v.Value.Content
		}
		res[k+"|tags"] = e.Tags
	}
	return res, s
}

func TestFieldKinds(t *testing.T) {
	got, _ := convertItems(t, itemWith("i", "Item",
		fieldOf("Mail", "email", map[string]any{"email_address": "a@b.example"}),
		fieldOf("Home", "address", map[string]any{
			"street": "1 Main St", "city": "Town", "state": "ST", "zip": "12345", "country": "ZA",
		}),
		fieldOf("Born", "date", 1700000000),
		fieldOf("Unset date", "date", 0),
		fieldOf("Count", "number", 42),
		fieldOf("Ratio", "number", 1.5),
		fieldOf("Flag", "checkbox", true),
		fieldOf("Nested", "string", map[string]any{"a": "b"}),
		fieldOf("Pin", "concealed", "9999"),
		map[string]any{"id": "by-id", "value": map[string]any{"string": "untitled"}},
		map[string]any{"title": "Two", "value": map[string]any{"string": "a", "number": 1}},
		map[string]any{"title": "None", "value": map[string]any{}},
	))

	for key, want := range map[string]string{
		"V/Item|Extra_Mail":  "a@b.example",
		"V/Item|Extra_Home":  "1 Main St\nTown, ST 12345\nZA",
		"V/Item|Extra_Born":  "2023-11-14",
		"V/Item|Extra_Count": "42",
		"V/Item|Extra_Ratio": "1.5",
		"V/Item|Extra_Flag":  "true",
		"V/Item|Extra_Pin":   "9999",
		"V/Item|Extra_by-id": "untitled",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	for _, key := range []string{"V/Item|Extra_Unset date", "V/Item|Extra_Nested", "V/Item|Extra_Two", "V/Item|Extra_None"} {
		if v, ok := got[key]; ok {
			t.Errorf("%s should be dropped, got %q", key, v)
		}
	}
}

func TestConcealedFieldIsProtected(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	write1pux(t, in, nil, vaultOf("v", "V", itemWith("i", "Item", fieldOf("Pin", "concealed", "9999"))))
	convertT(t, in, out)
	_, es := open(t, out)
	for _, v := range es["V/Item"].Values {
		if v.Key == "Extra_Pin" && !v.Value.Protected.Bool {
			t.Error("concealed field is not marked protected")
		}
	}
}

func TestItemStatesAndURLs(t *testing.T) {
	fav := itemWith("fav", "Fav")
	fav["favIndex"] = 1
	fav["overview"].(map[string]any)["tags"] = []any{"work"}
	arch := itemWith("arch", "Arch")
	arch["state"] = "archived"
	urls := itemWith("urls", "Urls")
	urls["overview"] = map[string]any{
		"title": "Urls", "url": "https://main.example",
		"urls": []any{
			map[string]any{"url": "https://main.example"},
			map[string]any{"url": "https://second.example"},
			map[string]any{"url": "https://third.example"},
		},
	}
	legacy := itemWith("legacy", "Legacy")
	legacy["details"].(map[string]any)["password"] = "legacy-pass"

	got, s := convertItems(t, fav, arch, urls, legacy)

	if s.entries != 4 {
		t.Errorf("entries = %d, want 4 (archived items are kept)", s.entries)
	}
	if got["V/Fav|tags"] != "work,Favorite" {
		t.Errorf("Fav tags = %q", got["V/Fav|tags"])
	}
	if got["V/Arch|tags"] != "Archived" {
		t.Errorf("Arch tags = %q", got["V/Arch|tags"])
	}
	if got["V/Urls|KP2A_URL_1"] != "https://second.example" || got["V/Urls|KP2A_URL_2"] != "https://third.example" {
		t.Errorf("extra URLs wrong: %q, %q", got["V/Urls|KP2A_URL_1"], got["V/Urls|KP2A_URL_2"])
	}
	if got["V/Legacy|Password"] != "legacy-pass" {
		t.Errorf("legacy password = %q", got["V/Legacy|Password"])
	}
}

func TestTOTPVariants(t *testing.T) {
	const full = "otpauth://totp/X:y?secret=ABC&issuer=X"
	got, _ := convertItems(t, itemWith("i", "Item",
		fieldOf("one", "totp", full),
		fieldOf("two", "totp", "SECRET2"),
		fieldOf("empty", "totp", ""),
	))
	if got["V/Item|otp"] != full {
		t.Errorf("otp = %q, want the otpauth URL unchanged", got["V/Item|otp"])
	}
	if !strings.Contains(got["V/Item|otp_1"], "secret=SECRET2") {
		t.Errorf("otp_1 = %q", got["V/Item|otp_1"])
	}
	if _, ok := got["V/Item|otp_2"]; ok {
		t.Error("empty totp created otp_2")
	}
}

func TestMissingAttachmentKeepsEntry(t *testing.T) {
	doc := itemWith("doc", "Doc")
	doc["details"].(map[string]any)["documentAttributes"] = map[string]any{"fileName": "gone.pdf", "documentId": "nope"}
	got, s := convertItems(t, doc)
	if s.entries != 1 || s.attachments != 0 {
		t.Errorf("stats = %+v, want 1 entry and 0 attachments", s)
	}
	if _, ok := got["V/Doc|tags"]; !ok {
		t.Error("entry with missing attachment was dropped")
	}
}

func TestKDFSurvivesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	baseExport(t, in, "p", 1700000000)
	convertT(t, in, out)
	db, _ := open(t, out)
	kdf := db.Header.FileHeaders.KdfParameters
	if kdf.Memory != 64<<20 || kdf.Iterations != 10 {
		t.Errorf("kdf memory=%d iterations=%d, want %d and 10", kdf.Memory, kdf.Iterations, 64<<20)
	}
}

// zipWith writes a zip with the given name->body entries.
func zipWith(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConvertErrors(t *testing.T) {
	dir := t.TempDir()
	notZip := filepath.Join(dir, "notzip.1pux")
	if err := os.WriteFile(notZip, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	noData := filepath.Join(dir, "nodata.1pux")
	zipWith(t, noData, map[string]string{"other.txt": "x"})
	badJSON := filepath.Join(dir, "badjson.1pux")
	zipWith(t, badJSON, map[string]string{"export.data": "{not json"})
	good := filepath.Join(dir, "good.1pux")
	baseExport(t, good, "p", 1700000000)

	cases := []struct {
		name, in, out, want string
	}{
		{"missing input", filepath.Join(dir, "missing"), filepath.Join(dir, "o1.kdbx"), "open 1pux"},
		{"not a zip", notZip, filepath.Join(dir, "o2.kdbx"), "open 1pux"},
		{"no export.data", noData, filepath.Join(dir, "o3.kdbx"), "not a 1pux file"},
		{"bad json", badJSON, filepath.Join(dir, "o4.kdbx"), "parse export.data"},
		{"unwritable output", good, filepath.Join(dir, "no-such-dir", "o5.kdbx"), "no-such-dir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := convert(c.in, c.out, "Backup", testPassword)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
			if _, statErr := os.Stat(c.out); statErr == nil && c.name != "unwritable output" {
				t.Error("output file was created despite the error")
			}
		})
	}
}

func TestMonthYear(t *testing.T) {
	got, _ := convertItems(t, itemWith("i", "Item",
		fieldOf("Expiry", "monthYear", 202311),
		fieldOf("Odd", "monthYear", 42),
	))
	if got["V/Item|Extra_Expiry"] != "2023-11" {
		t.Errorf("Expiry = %q, want 2023-11", got["V/Item|Extra_Expiry"])
	}
	if got["V/Item|Extra_Odd"] != "42" {
		t.Errorf("Odd = %q, want the raw value", got["V/Item|Extra_Odd"])
	}
}

// The 1Password docs show three underscores between document ID and file name,
// KeePassXC's importer uses two. Accept both.
func TestAttachmentSeparators(t *testing.T) {
	const payload = "attachment payload that is long enough to read back reliably"
	for name, sep := range map[string]string{"two": "__", "three": "___"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
			doc := itemWith("doc", "Doc")
			doc["details"].(map[string]any)["documentAttributes"] = map[string]any{"fileName": "p.pdf", "documentId": "d1"}
			write1pux(t, in, map[string]string{"d1" + sep + "p.pdf": payload}, vaultOf("v", "V", doc))
			s := convertT(t, in, out)
			if s.attachments != 1 {
				t.Fatalf("attachments = %d, want 1", s.attachments)
			}
			db, es := open(t, out)
			if got := attachment(t, db, es["V/Doc"], "p.pdf"); got != payload {
				t.Errorf("attachment = %q", got)
			}
		})
	}
}

// Shapes seen in a real export: ssoLogin is an object and address can be null.
func TestRealWorldShapes(t *testing.T) {
	got, _ := convertItems(t, itemWith("i", "Item",
		fieldOf("sign in with", "ssoLogin", map[string]any{"provider": "google", "item": "abc"}),
		fieldOf("sign in with other", "ssoLogin", map[string]any{"provider": "github"}),
		fieldOf("Home", "address", nil),
		fieldOf("Empty home", "address", map[string]any{"street": "", "city": "", "state": "", "zip": "", "country": ""}),
		fieldOf("Expiry", "monthYear", nil),
	))
	if got["V/Item|Extra_sign in with"] != "google" || got["V/Item|Extra_sign in with other"] != "github" {
		t.Errorf("ssoLogin not kept: %q, %q", got["V/Item|Extra_sign in with"], got["V/Item|Extra_sign in with other"])
	}
	for _, k := range []string{"Home", "Empty home", "Expiry"} {
		if v, ok := got["V/Item|Extra_"+k]; ok {
			t.Errorf("%s should be dropped, got %q", k, v)
		}
	}
}

// Two fields with the same title in one section (e.g. two SSO providers) must
// both survive under distinct keys.
func TestDuplicateFieldNames(t *testing.T) {
	got, _ := convertItems(t, itemWith("i", "Item",
		fieldOf("sign in with", "ssoLogin", map[string]any{"provider": "google"}),
		fieldOf("sign in with", "ssoLogin", map[string]any{"provider": "github"}),
		fieldOf("note", "string", "one"),
		fieldOf("note", "string", "two"),
		fieldOf("note", "string", "three"),
	))
	vals := map[string]bool{}
	for k, v := range got {
		if strings.HasPrefix(k, "V/Item|Extra_") {
			vals[v] = true
		}
	}
	for _, want := range []string{"google", "github", "one", "two", "three"} {
		if !vals[want] {
			t.Errorf("value %q was lost; got %v", want, got)
		}
	}
}

func TestPasswordHistory(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	it := login("bank", "Bank", "me", "current", 1700000900)
	// 1Password does not promise an order, so feed it newest first.
	it["details"].(map[string]any)["passwordHistory"] = []any{
		map[string]any{"value": "second", "time": 1700000500},
		map[string]any{"value": "first", "time": 1700000100},
	}
	write1pux(t, in, nil, vaultOf("v", "V", it))
	convertT(t, in, out)
	_, es := open(t, out)
	bank := es["V/Bank"]

	if bank.GetPassword() != "current" {
		t.Errorf("current password = %q", bank.GetPassword())
	}
	if len(bank.Histories) != 1 || len(bank.Histories[0].Entries) != 2 {
		t.Fatalf("histories = %+v, want one History with 2 snapshots", bank.Histories)
	}
	for i, want := range []struct {
		pass  string
		mtime int64
	}{{"first", 1700000100}, {"second", 1700000500}} {
		h := bank.Histories[0].Entries[i]
		if h.GetPassword() != want.pass || h.Times.LastModificationTime.Time.Unix() != want.mtime {
			t.Errorf("snapshot %d = %q @ %d, want %q @ %d", i, h.GetPassword(),
				h.Times.LastModificationTime.Time.Unix(), want.pass, want.mtime)
		}
		if h.UUID != bank.UUID || h.GetContent("UserName") != "me" {
			t.Errorf("snapshot %d is not a copy of the entry", i)
		}
	}
}

func TestSSOReference(t *testing.T) {
	ref := func(vault, item string) map[string]any {
		return map[string]any{"provider": "google", "item": map[string]any{"vaultUuid": vault, "itemUuid": item}}
	}
	site := itemWith("site", "Site",
		fieldOf("sign in with", "ssoLogin", ref("v2", "google-login")),
		fieldOf("other", "ssoLogin", ref("v2", "not-exported")),
		fieldOf("binned", "ssoLogin", ref("v2", "trashed-login")),
	)
	trashed := login("trashed-login", "Old Google", "old@gmail.example", "p", 1700000000)
	trashed["state"] = "trashed"
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	write1pux(t, in, nil,
		vaultOf("v1", "One", site),
		vaultOf("v2", "Two", login("google-login", "Google", "me@gmail.example", "p", 1700000000), trashed),
	)
	convertT(t, in, out)
	_, es := open(t, out)
	s, g := es["One/Site"], es["Two/Google"]

	u := g.UUID
	want := "{REF:U@I:" + strings.ToUpper(hex.EncodeToString(u[:])) + "}"
	if got := s.GetContent("Extra_sign in with account"); got != want {
		t.Errorf("reference = %q, want %q", got, want)
	}
	if got := s.GetContent("Extra_sign in with"); got != "google" {
		t.Errorf("provider = %q", got)
	}
	if v := s.Get("Extra_other account"); v != nil {
		t.Errorf("reference to an item outside the export = %q, want none", v.Value.Content)
	}
	if v := s.Get("Extra_binned account"); v != nil {
		t.Errorf("reference to a trashed item = %q, want none", v.Value.Content)
	}
	if got := s.GetContent("Extra_binned"); got != "google" {
		t.Errorf("provider for a trashed link = %q, want it kept", got)
	}
}

func TestCardNumberProtected(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	write1pux(t, in, nil, vaultOf("v", "V", itemWith("i", "Card", fieldOf("number", "creditCardNumber", "4111111111111111"))))
	convertT(t, in, out)
	_, es := open(t, out)
	card := es["V/Card"]
	v := card.Get("Extra_number")
	if v == nil || v.Value.Content != "4111111111111111" || !v.Value.Protected.Bool {
		t.Errorf("card number = %+v, want protected 4111111111111111", v)
	}
}

// KeePassXC reports the root group's creation time as the database creation
// date, so it must come from the export, not the Unix epoch.
func TestRootGroupTimes(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	old := login("old", "Old", "u", "p", 1650000000)
	old["createdAt"] = 1500000000
	write1pux(t, in, nil,
		vaultOf("v1", "One", old, login("mid", "Mid", "u", "p", 1700000000)),
		vaultOf("v2", "Two", login("new", "New", "u", "p", 1750000000)),
		vaultOf("v3", "Empty"),
	)
	convertT(t, in, out)
	db, _ := open(t, out)
	root := db.Content.Root.Groups[0].Times
	if got := root.CreationTime.Time.Unix(); got != 1500000000 {
		t.Errorf("root created = %d, want 1500000000 (earliest item)", got)
	}
	if got := root.LastModificationTime.Time.Unix(); got != 1750000000 {
		t.Errorf("root modified = %d, want 1750000000 (latest item)", got)
	}
}
