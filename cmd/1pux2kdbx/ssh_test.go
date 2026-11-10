package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testEd25519 returns a fixed ed25519 key as 1Password exports it: a PKCS#8
// PEM private key plus the OpenSSH public key line and fingerprint.
func testEd25519(t *testing.T) (pkcs8PEM, public, fingerprint string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(sshString([]byte("ssh-ed25519")), sshString(priv.Public().(ed25519.PublicKey))...)
	sum := sha256.Sum256(blob)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob),
		"SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func sshItem(id, title, private string, metadata map[string]any) map[string]any {
	return itemWith(id, title, fieldOf("private key", "sshKey", map[string]any{
		"privateKey": private, "metadata": metadata,
	}))
}

// sshKeygen runs ssh-keygen with the given flags on a private key and returns
// its stdout, so tests check what OpenSSH itself makes of the stored key.
func sshKeygen(t *testing.T, key []byte, flags ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, key, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh-keygen", append(flags, "-f", p)...).Output()
	if err != nil {
		t.Fatalf("ssh-keygen %v cannot use the stored key: %v", flags, err)
	}
	return string(out)
}

func attachmentBytes(t *testing.T, path, entry, name string) []byte {
	t.Helper()
	db, es := open(t, path)
	return []byte(attachment(t, db, es[entry], name))
}

func TestSSHKeyParts(t *testing.T) {
	priv, public, fp := testEd25519(t)
	const rsa = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
	meta := func(keyType any) map[string]json.RawMessage {
		m := map[string]json.RawMessage{}
		for k, v := range map[string]any{"publicKey": public, "fingerprint": fp, "keyType": keyType} {
			m[k], _ = json.Marshal(v)
		}
		return m
	}
	names := func(fs []namedFile) (out []string) {
		for _, f := range fs {
			out = append(out, f.name)
		}
		return out
	}

	ed := sshKeyParts(sshKey{PrivateKey: priv, Metadata: meta("ed25519")})
	if got := names(ed.files); !slices.Equal(got, []string{"id_ed25519", "id_ed25519.pkcs8"}) {
		t.Errorf("ed25519 files = %v", got)
	} else if string(ed.files[1].data) != priv || !bytes.HasPrefix(ed.files[0].data, []byte("-----BEGIN OPENSSH")) {
		t.Error("ed25519: want the OpenSSH key first and the original PKCS#8 bytes second")
	}
	if ed.agentKey != "id_ed25519" || ed.publicKey != public || ed.fingerprint != fp {
		t.Errorf("ed25519 = %+v", ed)
	}

	// Real exports give the RSA keyType as an object, and its key needs no conversion.
	r := sshKeyParts(sshKey{PrivateKey: rsa, Metadata: meta(map[string]any{"rsa": "Rsa3072"})})
	if got := names(r.files); !slices.Equal(got, []string{"id_rsa"}) || string(r.files[0].data) != rsa || r.agentKey != "id_rsa" {
		t.Errorf("rsa = %+v", r)
	}

	none := sshKeyParts(sshKey{Metadata: meta("ed25519")})
	if len(none.files) != 0 || none.agentKey != "" || none.publicKey != public {
		t.Errorf("no private key = %+v, want only the public key", none)
	}
}

func TestKeeAgentSettings(t *testing.T) {
	var k keeAgent
	if err := xml.Unmarshal(keeAgentSettings("id_<odd>&"), &k); err != nil {
		t.Fatal(err)
	}
	if !k.Allow || !k.AddOpen || !k.RmClose || k.Location.Type != "attachment" || k.Location.Attachment != "id_<odd>&" {
		t.Errorf("settings = %+v", k)
	}
}

func TestSSHEd25519(t *testing.T) {
	priv, public, fp := testEd25519(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "a.1pux")
	write1pux(t, in, nil, vaultOf("v", "V", sshItem("k", "Key", priv, map[string]any{
		"privateKey": priv, "publicKey": public, "fingerprint": fp, "keyType": "ed25519",
	})))
	out1, out2 := filepath.Join(dir, "1.kdbx"), filepath.Join(dir, "2.kdbx")
	convertT(t, in, out1)
	convertT(t, in, out2)

	key := attachmentBytes(t, out1, "V/Key", "id_ed25519")
	if !strings.HasPrefix(string(key), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("id_ed25519 is not in OpenSSH format:\n%s", key)
	}
	if orig := attachmentBytes(t, out1, "V/Key", "id_ed25519.pkcs8"); string(orig) != priv {
		t.Errorf("id_ed25519.pkcs8 is not the original export bytes")
	}
	// Stable output keeps merges quiet.
	if again := attachmentBytes(t, out2, "V/Key", "id_ed25519"); !bytes.Equal(key, again) {
		t.Error("converted key differs between two conversions of the same export")
	}

	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not found")
	}
	if got := strings.TrimSpace(sshKeygen(t, key, "-y")); got != public {
		t.Errorf("ssh-keygen -y = %q, want %q", got, public)
	}
	if got := sshKeygen(t, key, "-l", "-E", "sha256"); !strings.Contains(got, fp) {
		t.Errorf("ssh-keygen -l = %q, want fingerprint %s", got, fp)
	}
}

func TestSSHRSA(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not found")
	}
	dir := t.TempDir()
	kp := filepath.Join(dir, "id_rsa")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-C", "", "-f", kp).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	priv, err := os.ReadFile(kp)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(kp + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	public := strings.TrimSpace(string(pub))

	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	// Real exports give the RSA keyType as an object, not a string.
	write1pux(t, in, nil, vaultOf("v", "V", sshItem("k", "Key", string(priv), map[string]any{
		"privateKey": string(priv), "publicKey": public, "fingerprint": "SHA256:x", "keyType": map[string]any{"rsa": "Rsa3072"},
	})))
	convertT(t, in, out)

	_, es := open(t, out)
	e := es["V/Key"]
	if got := e.GetContent("SSH Public Key"); got != public {
		t.Errorf("SSH Public Key = %q, want %q", got, public)
	}
	key := attachmentBytes(t, out, "V/Key", "id_rsa")
	if !bytes.Equal(key, priv) {
		t.Error("an OpenSSH-format key must be stored byte for byte")
	}
	if got := strings.TrimSpace(sshKeygen(t, key, "-y")); got != public {
		t.Errorf("ssh-keygen -y = %q, want %q", got, public)
	}
	for _, ref := range e.Binaries {
		if strings.HasSuffix(ref.Name, ".pkcs8") {
			t.Errorf("unexpected %s for a key that needed no conversion", ref.Name)
		}
	}
}

// keeAgent is the part of KeePassXC's KeeAgent.settings that decides whether
// and how a key is loaded into the SSH agent.
type keeAgent struct {
	XMLName  xml.Name `xml:"EntrySettings"`
	Allow    bool     `xml:"AllowUseOfSshKey"`
	AddOpen  bool     `xml:"AddAtDatabaseOpen"`
	RmClose  bool     `xml:"RemoveAtDatabaseClose"`
	Location struct {
		Type       string `xml:"SelectedType"`
		Attachment string `xml:"AttachmentName"`
	} `xml:"Location"`
}

func TestSSHAgentSettings(t *testing.T) {
	priv, public, fp := testEd25519(t)
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	write1pux(t, in, nil, vaultOf("v", "V",
		sshItem("ed", "Ed", priv, map[string]any{"publicKey": public, "fingerprint": fp, "keyType": "ed25519"}),
		sshItem("rsa", "Rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
			map[string]any{"publicKey": "ssh-rsa AAAA", "keyType": map[string]any{"rsa": "Rsa3072"}}),
		sshItem("none", "None", "", map[string]any{"publicKey": "ssh-ed25519 AAAA", "keyType": "ed25519"}),
	))
	s := convertT(t, in, out)
	if s.attachments != 3 {
		t.Errorf("attachments = %d, want 3 (settings are not counted)", s.attachments)
	}

	db, es := open(t, out)
	for entry, want := range map[string]string{"V/Ed": "id_ed25519", "V/Rsa": "id_rsa"} {
		var k keeAgent
		if err := xml.Unmarshal([]byte(attachment(t, db, es[entry], "KeeAgent.settings")), &k); err != nil {
			t.Fatalf("%s: KeeAgent.settings: %v", entry, err)
		}
		if !k.Allow || !k.AddOpen || !k.RmClose || k.Location.Type != "attachment" || k.Location.Attachment != want {
			t.Errorf("%s: settings = %+v, want enabled, add on open, remove on close, attachment %s", entry, k, want)
		}
	}
	for _, ref := range es["V/None"].Binaries {
		if ref.Name == "KeeAgent.settings" {
			t.Error("KeeAgent.settings added for an item without a private key")
		}
	}
}
