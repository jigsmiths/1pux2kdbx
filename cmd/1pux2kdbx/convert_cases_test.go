package main

import (
	"archive/zip"
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
