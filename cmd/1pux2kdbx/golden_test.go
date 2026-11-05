package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	kp "github.com/tobischo/gokeepasslib/v3"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json from the current output")

// zipDir packs dir into a .1pux the way 1Password lays it out.
func zipDir(t *testing.T, dir, dest string) {
	t.Helper()
	f, err := os.Create(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

type dumpValue struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Protected bool   `json:"protected,omitempty"`
}

type dumpBinary struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type dumpEntry struct {
	UUID     string       `json:"uuid"`
	Tags     string       `json:"tags,omitempty"`
	Created  int64        `json:"created"`
	Modified int64        `json:"modified"`
	Values   []dumpValue  `json:"values"`
	Binaries []dumpBinary `json:"binaries,omitempty"`
	// History is "<modified unix time> <password>" per snapshot, oldest first.
	History []string `json:"history,omitempty"`
}

type dumpGroup struct {
	UUID    string               `json:"uuid"`
	Entries map[string]dumpEntry `json:"entries"`
}

type dump struct {
	Name   string               `json:"name"`
	Groups map[string]dumpGroup `json:"groups"`
}

func dumpDB(t *testing.T, path string) []byte {
	t.Helper()
	db, _ := open(t, path)
	root := db.Content.Root.Groups[0]
	d := dump{Name: root.Name, Groups: map[string]dumpGroup{}}
	for _, g := range root.Groups {
		dg := dumpGroup{UUID: uuidStr(g.UUID), Entries: map[string]dumpEntry{}}
		for _, e := range g.Entries {
			de := dumpEntry{
				UUID: uuidStr(e.UUID), Tags: e.Tags,
				Created: e.Times.CreationTime.Time.Unix(), Modified: e.Times.LastModificationTime.Time.Unix(),
			}
			for _, v := range e.Values {
				de.Values = append(de.Values, dumpValue{v.Key, v.Value.Content, v.Value.Protected.Bool})
			}
			for _, ref := range e.Binaries {
				b, err := db.FindBinary(ref.Value.ID).GetContentBytes()
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(b)
				de.Binaries = append(de.Binaries, dumpBinary{ref.Name, len(b), hex.EncodeToString(sum[:8])})
			}
			for _, h := range e.Histories {
				for _, s := range h.Entries {
					de.History = append(de.History, fmt.Sprintf("%d %s", s.Times.LastModificationTime.Time.Unix(), s.GetPassword()))
				}
			}
			dg.Entries[e.GetTitle()] = de
		}
		d.Groups[g.Name] = dg
	}
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func uuidStr(u kp.UUID) string {
	return hex.EncodeToString(u[:])
}

// TestGolden converts testdata/spec, an export laid out like the 1Password
// 1PUX docs describe, and compares the result with the reviewed golden file.
// Run `go test -run TestGolden -update` after an intended output change and
// review the diff.
func TestGolden(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "spec.1pux"), filepath.Join(dir, "spec.kdbx")
	zipDir(t, filepath.Join("testdata", "spec"), in)
	s := convertT(t, in, out)
	if s.groups != 2 || s.entries != 9 || s.skipped != 1 || s.attachments != 3 {
		t.Errorf("stats = %+v, want 2 groups, 9 entries, 1 skipped, 3 attachments", s)
	}

	got := dumpDB(t, out)
	golden := filepath.Join("testdata", "spec.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s; run with -update and review the diff\n--- got ---\n%s", golden, got)
	}
}

// TestRealExport converts a user-supplied export and checks it against the
// export's own contents. It never reads anything from the repo, so a real
// export stays out of git:
//
//	ONEPUX_FIXTURE=~/Downloads/1PasswordExport.1pux go test -run TestRealExport -v
func TestRealExport(t *testing.T) {
	in := os.Getenv("ONEPUX_FIXTURE")
	if in == "" {
		t.Skip("set ONEPUX_FIXTURE to a real .1pux export to run this")
	}

	// Count items straight from the raw JSON, independent of the converter.
	zr, err := zip.OpenReader(in)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Accounts []struct {
			Vaults []struct {
				Items []struct {
					State   string `json:"state"`
					Details struct {
						Sections []struct {
							Fields []struct {
								Value map[string]json.RawMessage `json:"value"`
							} `json:"fields"`
						} `json:"sections"`
					} `json:"details"`
				} `json:"items"`
			} `json:"vaults"`
		} `json:"accounts"`
	}
	var total, trashed, sshKeys int
	for _, f := range zr.File {
		if f.Name != "export.data" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
	}
	_ = zr.Close()
	groups := 0
	for _, a := range raw.Accounts {
		for _, v := range a.Vaults {
			groups++
			for _, it := range v.Items {
				total++
				if it.State == "trashed" {
					trashed++
					continue
				}
				for _, s := range it.Details.Sections {
					for _, f := range s.Fields {
						if _, ok := f.Value["sshKey"]; ok {
							sshKeys++
						}
					}
				}
			}
		}
	}

	// Capture stderr to catch missing-attachment warnings.
	r, w, _ := os.Pipe()
	orig := os.Stderr
	os.Stderr = w
	out := filepath.Join(t.TempDir(), "real.kdbx")
	s, err := convert(in, out, "Backup", testPassword)
	os.Stderr = orig
	_ = w.Close()
	warnings, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%d groups, %d entries, %d attachments, %d skipped", s.groups, s.entries, s.attachments, s.skipped)
	if s.groups != groups {
		t.Errorf("groups = %d, export has %d vaults", s.groups, groups)
	}
	if s.entries != total-trashed || s.skipped != trashed {
		t.Errorf("entries/skipped = %d/%d, export has %d items of which %d trashed", s.entries, s.skipped, total, trashed)
	}
	if strings.Contains(string(warnings), "missing attachment") {
		t.Errorf("attachments not found in the archive:\n%s", warnings)
	}

	// The output must decode and hold the same number of entries.
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	db := kp.NewDatabase()
	db.Credentials = kp.NewPasswordCredentials(testPassword)
	if err := kp.NewDecoder(f).Decode(db); err != nil {
		t.Fatalf("decode converted file: %v", err)
	}
	count := 0
	for _, g := range db.Content.Root.Groups[0].Groups {
		count += len(g.Entries)
	}
	if count != s.entries {
		t.Errorf("kdbx holds %d entries, converter reported %d", count, s.entries)
	}

	// Every SSH key must be one OpenSSH can load and must match the public
	// key 1Password exported for it.
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Log("ssh-keygen not found, skipping the SSH key check")
	} else {
		checked := 0
		for _, g := range db.Content.Root.Groups[0].Groups {
			for i := range g.Entries {
				e := &g.Entries[i]
				pub := strings.Fields(e.GetContent("SSH Public Key"))
				agentKey := ""
				for _, ref := range e.Binaries {
					if ref.Name != "KeeAgent.settings" {
						continue
					}
					b, err := db.FindBinary(ref.Value.ID).GetContentBytes()
					var k keeAgent
					if err != nil || xml.Unmarshal(b, &k) != nil || !k.Allow || !k.AddOpen || k.Location.Type != "attachment" {
						t.Errorf("%s: KeeAgent.settings is not a valid enabled agent config", e.GetTitle())
					}
					agentKey = k.Location.Attachment
				}
				for _, ref := range e.Binaries {
					if !strings.HasPrefix(ref.Name, "id_") || strings.HasSuffix(ref.Name, ".pkcs8") {
						continue
					}
					key, err := db.FindBinary(ref.Value.ID).GetContentBytes()
					if err != nil {
						t.Fatal(err)
					}
					got := strings.Fields(sshKeygen(t, key, "-y"))
					if len(pub) < 2 || len(got) < 2 || got[0] != pub[0] || got[1] != pub[1] {
						t.Errorf("%s: %s does not match its exported public key", e.GetTitle(), ref.Name)
					}
					if agentKey != ref.Name {
						t.Errorf("%s: SSH agent points at %q, want %q", e.GetTitle(), agentKey, ref.Name)
					}
					checked++
				}
			}
		}
		t.Logf("%d of %d SSH keys load in OpenSSH, match their public key and are set up for the KeePassXC agent", checked, sshKeys)
		if checked != sshKeys {
			t.Errorf("checked %d SSH keys, export has %d", checked, sshKeys)
		}
	}

	// The Go decoder is lenient; KeePassXC is the reader that matters.
	cli := os.Getenv("KEEPASSXC_CLI")
	if cli == "" {
		cli = "keepassxc-cli"
	}
	if _, err := exec.LookPath(cli); err != nil {
		t.Log("keepassxc-cli not found, skipping the KeePassXC open check")
		return
	}
	cmd := exec.Command(cli, "export", "-f", "xml", out)
	cmd.Stdin = strings.NewReader(testPassword + "\n")
	xml, err := cmd.Output()
	if err != nil {
		t.Fatalf("keepassxc-cli cannot open the converted file: %v", err)
	}
	if n := strings.Count(string(xml), "<Entry>"); n < s.entries {
		t.Errorf("keepassxc-cli sees %d entries, want at least %d", n, s.entries)
	}
}
