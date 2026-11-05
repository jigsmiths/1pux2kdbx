package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	kp "github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// Minimal view of export.data. Only the fields we map are declared; the JSON
// decoder ignores the rest.
type export struct {
	Accounts []struct {
		Vaults []vault `json:"vaults"`
	} `json:"accounts"`
}

type vault struct {
	Attrs struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
	} `json:"attrs"`
	Items []item `json:"items"`
}

type item struct {
	UUID      string `json:"uuid"`
	FavIndex  int    `json:"favIndex"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
	State     string `json:"state"`
	Overview  struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		URLs  []struct {
			URL string `json:"url"`
		} `json:"urls"`
		Tags []string `json:"tags"`
	} `json:"overview"`
	Details struct {
		LoginFields []struct {
			Designation string `json:"designation"`
			Value       string `json:"value"`
		} `json:"loginFields"`
		Password           string           `json:"password"`
		NotesPlain         string           `json:"notesPlain"`
		Sections           []section        `json:"sections"`
		DocumentAttributes *document        `json:"documentAttributes"`
		PasswordHistory    []passwordChange `json:"passwordHistory"`
	} `json:"details"`
}

type passwordChange struct {
	Value string `json:"value"`
	Time  int64  `json:"time"`
}

type section struct {
	Title  string  `json:"title"`
	Fields []field `json:"fields"`
}

// A field value is an object with exactly one key naming its type, e.g.
// {"concealed": "secret"} or {"file": {"documentId": ..., "fileName": ...}}.
type field struct {
	Title string                     `json:"title"`
	ID    string                     `json:"id"`
	Value map[string]json.RawMessage `json:"value"`
}

type document struct {
	FileName   string `json:"fileName"`
	DocumentID string `json:"documentId"`
}

// Metadata values are not all strings: RSA keys give keyType as {"rsa": "Rsa3072"}.
type sshKey struct {
	PrivateKey string                     `json:"privateKey"`
	Metadata   map[string]json.RawMessage `json:"metadata"`
}

type stats struct{ groups, entries, attachments, skipped int }

// converter carries the open zip and the database being built so the
// per-item helpers stay small.
type converter struct {
	zip   *zip.ReadCloser
	db    *kp.Database
	stats stats
	items itemIndex
}

// itemIndex maps every converted item to its entry UUID. It is built before
// any entry so references can point at entries not yet created.
type itemIndex map[string]kp.UUID

func newItemIndex(ex export) itemIndex {
	idx := itemIndex{}
	for _, acc := range ex.Accounts {
		for _, v := range acc.Vaults {
			for _, it := range v.Items {
				if it.State != "trashed" {
					// Item UUIDs are only unique within a vault, so scope them by vault.
					idx[v.Attrs.UUID+":"+it.UUID] = stableUUID(v.Attrs.UUID + ":" + it.UUID)
				}
			}
		}
	}
	return idx
}

// entryUUID reports the entry UUID for an item, and false if the item is not
// converted (trashed, or not in the export).
func (idx itemIndex) entryUUID(vault, item string) (kp.UUID, bool) {
	u, ok := idx[vault+":"+item]
	return u, ok
}

func convert(in, out, name, password string) (stats, error) {
	zr, err := zip.OpenReader(in)
	if err != nil {
		return stats{}, fmt.Errorf("open 1pux: %w", err)
	}
	defer func() { _ = zr.Close() }()

	c := &converter{zip: zr, db: kp.NewDatabase(kp.WithDatabaseKDBXVersion41())}
	// gokeepasslib defaults to Argon2 with 1 MiB, far below KeePassXC. On first
	// run this file becomes the long-lived backup and merges keep its KDF, so
	// match KeePassXC's defaults.
	kdf := c.db.Header.FileHeaders.KdfParameters
	kdf.Memory = 64 << 20
	kdf.Iterations = 10

	data, err := c.readFile("export.data")
	if err != nil {
		return stats{}, fmt.Errorf("not a 1pux file: %w", err)
	}
	var ex export
	if err := json.Unmarshal(data, &ex); err != nil {
		return stats{}, fmt.Errorf("parse export.data: %w", err)
	}

	c.items = newItemIndex(ex)

	root := kp.NewGroup()
	root.Name = name
	root.UUID = stableUUID("root")
	var created, updated int64
	for _, acc := range ex.Accounts {
		for _, v := range acc.Vaults {
			g := c.group(v)
			root.Groups = append(root.Groups, g)
			if len(g.Entries) == 0 {
				continue
			}
			if gc := g.Times.CreationTime.Time.Unix(); created == 0 || gc < created {
				created = gc
			}
			updated = max(updated, g.Times.LastModificationTime.Time.Unix())
		}
	}
	// KeePassXC shows this as the database creation date.
	root.Times = times(created, updated)

	c.db.Credentials = kp.NewPasswordCredentials(password)
	c.db.Content.Meta.DatabaseName = name
	c.db.Content.Root.Groups = []kp.Group{root}
	if err := c.db.LockProtectedEntries(); err != nil {
		return stats{}, err
	}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return stats{}, err
	}
	if err := kp.NewEncoder(f).Encode(c.db); err != nil {
		_ = f.Close()
		return stats{}, fmt.Errorf("write kdbx: %w", err)
	}
	// A failed close on a written file can mean a truncated backup.
	if err := f.Close(); err != nil {
		return stats{}, fmt.Errorf("write kdbx: %w", err)
	}
	return c.stats, nil
}

func (c *converter) group(v vault) kp.Group {
	g := kp.NewGroup()
	g.UUID = stableUUID(v.Attrs.UUID)
	g.Name = v.Attrs.Name
	c.stats.groups++
	var created, updated int64
	for _, it := range v.Items {
		u, ok := c.items.entryUUID(v.Attrs.UUID, it.UUID)
		if !ok {
			c.stats.skipped++
			continue
		}
		g.Entries = append(g.Entries, c.entry(u, it))
		c.stats.entries++
		if created == 0 || it.CreatedAt < created {
			created = it.CreatedAt
		}
		updated = max(updated, it.UpdatedAt)
	}
	g.Times = times(created, updated)
	return g
}

func (c *converter) entry(u kp.UUID, it item) kp.Entry {
	e := kp.NewEntry()
	e.UUID = u

	set(&e, "Title", it.Overview.Title, false)
	set(&e, "URL", it.Overview.URL, false)
	set(&e, "Notes", it.Details.NotesPlain, false)
	for _, lf := range it.Details.LoginFields {
		switch strings.ToLower(lf.Designation) {
		case "username":
			set(&e, "UserName", lf.Value, false)
		case "password":
			set(&e, "Password", lf.Value, true)
		}
	}
	if e.GetPassword() == "" {
		set(&e, "Password", it.Details.Password, true)
	}
	extra := 0
	for _, u := range it.Overview.URLs {
		if u.URL != it.Overview.URL {
			extra++
			set(&e, fmt.Sprintf("KP2A_URL_%d", extra), u.URL, false)
		}
	}

	tags := append([]string{}, it.Overview.Tags...)
	if it.FavIndex > 0 {
		tags = append(tags, "Favorite")
	}
	if it.State == "archived" {
		tags = append(tags, "Archived")
	}
	e.Tags = strings.Join(tags, ",")

	for _, s := range it.Details.Sections {
		for _, f := range s.Fields {
			c.field(&e, s, f)
		}
	}
	if d := it.Details.DocumentAttributes; d != nil {
		c.attach(&e, *d)
	}

	e.Times = times(it.CreatedAt, it.UpdatedAt)
	e.Histories = history(e, it)
	return e
}

// history turns 1Password's password history into KeePass history snapshots,
// oldest first. 1Password keeps only old passwords, so each snapshot is the
// current entry with that password swapped in.
func history(e kp.Entry, it item) []kp.History {
	changes := append([]passwordChange(nil), it.Details.PasswordHistory...)
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].Time < changes[j].Time })
	var snaps []kp.Entry
	for _, ch := range changes {
		if ch.Value == "" {
			continue
		}
		s := e
		s.Values = nil
		for _, v := range e.Values {
			if v.Key != "Password" {
				s.Values = append(s.Values, v)
			}
		}
		set(&s, "Password", ch.Value, true)
		s.Times = times(it.CreatedAt, ch.Time)
		snaps = append(snaps, s)
	}
	if len(snaps) == 0 {
		return nil
	}
	return []kp.History{{Entries: snaps}}
}

// field maps one 1Password section field onto the entry. The attribute name is
// "<section title>_<field title>" to match KeePassXC's own importer.
func (c *converter) field(e *kp.Entry, s section, f field) {
	if len(f.Value) != 1 {
		return
	}
	name := f.Title
	if name == "" {
		name = f.ID
	}
	if s.Title != "" {
		name = s.Title + "_" + name
	}

	for kind, raw := range f.Value {
		switch kind {
		case "totp":
			c.totp(e, str(raw))
		case "file":
			var d document
			if json.Unmarshal(raw, &d) == nil {
				c.attach(e, d)
			}
		case "sshKey":
			var k sshKey
			if json.Unmarshal(raw, &k) == nil {
				c.sshKey(e, k)
			}
		case "email":
			var m struct {
				Address string `json:"email_address"`
			}
			if json.Unmarshal(raw, &m) == nil {
				set(e, name, m.Address, false)
			}
		case "address":
			var a map[string]string
			if json.Unmarshal(raw, &a) == nil && strings.Join([]string{a["street"], a["city"], a["state"], a["zip"], a["country"]}, "") != "" {
				set(e, name, fmt.Sprintf("%s\n%s, %s %s\n%s",
					a["street"], a["city"], a["state"], a["zip"], a["country"]), false)
			}
		case "ssoLogin":
			var m struct {
				Provider string          `json:"provider"`
				Item     json.RawMessage `json:"item"`
			}
			if json.Unmarshal(raw, &m) == nil {
				set(e, name, m.Provider, false)
				// Decoded separately so an unexpected link shape keeps the provider.
				var ref struct {
					Vault string `json:"vaultUuid"`
					Item  string `json:"itemUuid"`
				}
				// A KeePass field reference, which KeePassXC resolves to the
				// username of the linked login.
				if json.Unmarshal(m.Item, &ref) == nil {
					if u, ok := c.items.entryUUID(ref.Vault, ref.Item); ok {
						set(e, name+" account", "{REF:U@I:"+strings.ToUpper(hex.EncodeToString(u[:]))+"}", false)
					}
				}
			}
		case "date":
			if n, err := strconv.ParseInt(string(raw), 10, 64); err == nil && n > 0 {
				set(e, name, unix(n).Time.Format("2006-01-02"), false)
			}
		case "monthYear":
			// Stored as YYYYMM, not a timestamp.
			v := str(raw)
			if n, err := strconv.Atoi(v); err == nil && n >= 190001 && n%100 >= 1 && n%100 <= 12 {
				v = fmt.Sprintf("%04d-%02d", n/100, n%100)
			}
			set(e, name, v, false)
		default:
			set(e, name, str(raw), kind == "concealed" || kind == "creditCardNumber")
		}
	}
}

// totp stores the first secret as KeePassXC's "otp" attribute and any further
// ones as otp_1, otp_2, ...
func (c *converter) totp(e *kp.Entry, secret string) {
	if secret == "" {
		return
	}
	if !strings.HasPrefix(secret, "otpauth://") {
		secret = fmt.Sprintf("otpauth://totp/%s:%s?secret=%s",
			url.PathEscape(e.GetTitle()), url.PathEscape(e.GetContent("UserName")), url.QueryEscape(secret))
	}
	key := "otp"
	for i := 1; e.Get(key) != nil; i++ {
		key = fmt.Sprintf("otp_%d", i)
	}
	set(e, key, secret, true)
}

func (c *converter) sshKey(e *kp.Entry, k sshKey) {
	keyType := str(k.Metadata["keyType"])
	if keyType == "" {
		var obj map[string]json.RawMessage
		if json.Unmarshal(k.Metadata["keyType"], &obj) == nil {
			for t := range obj {
				if keyType == "" || t < keyType {
					keyType = t
				}
			}
		}
	}
	name := "id_" + keyType
	// OpenSSH cannot load the PKCS#8 form 1Password uses for ed25519, so store
	// it converted, plus the original bytes untouched.
	if converted, ok := openSSHEd25519(k.PrivateKey); ok {
		c.attachBytes(e, name, converted)
		c.attachBytes(e, name+".pkcs8", []byte(k.PrivateKey))
	} else {
		c.attachBytes(e, name, []byte(k.PrivateKey))
	}
	if k.PrivateKey != "" {
		c.keeAgent(e, name)
	}
	set(e, "SSH Public Key", str(k.Metadata["publicKey"]), false)
	set(e, "SSH Fingerprint", str(k.Metadata["fingerprint"]), false)
}

// keeAgent enables KeePassXC's SSH agent for the key attachment: added when
// the database opens, removed when it closes. KeePassXC supports one key per
// entry, so only the first key gets settings. Not counted in stats, which
// track data from the export.
func (c *converter) keeAgent(e *kp.Entry, attachment string) {
	const settings = "KeeAgent.settings"
	for _, ref := range e.Binaries {
		if ref.Name == settings {
			return
		}
	}
	var name strings.Builder
	_ = xml.EscapeText(&name, []byte(attachment))
	// Same layout as KeePassXC's KeeAgentSettings::toXml.
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>` + name.String() + `</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
    <FileName/>
  </Location>
</EntrySettings>
`
	bin := c.db.AddBinary([]byte(doc))
	e.Binaries = append(e.Binaries, bin.CreateReference(settings))
}

// openSSHEd25519 re-encodes a PKCS#8 ed25519 key in OpenSSH's own format
// (PROTOCOL.key). The key material is unchanged. The check bytes, random in
// ssh-keygen, are derived from the key so the output is stable across runs.
func openSSHEd25519(pemKey string) ([]byte, bool) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, false
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	priv, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, false
	}
	pubBlob := append(sshString([]byte("ssh-ed25519")), sshString(priv.Public().(ed25519.PublicKey))...)

	check := sha256.Sum256(priv.Seed())
	section := append(append([]byte{}, check[:4]...), check[:4]...)
	section = append(section, pubBlob...)
	section = append(section, sshString(priv)...)
	section = append(section, sshString(nil)...) // comment
	for pad := byte(1); len(section)%8 != 0; pad++ {
		section = append(section, pad)
	}

	out := []byte("openssh-key-v1\x00")
	out = append(out, sshString([]byte("none"))...) // cipher
	out = append(out, sshString([]byte("none"))...) // kdf
	out = append(out, sshString(nil)...)            // kdf options
	out = binary.BigEndian.AppendUint32(out, 1)     // number of keys
	out = append(out, sshString(pubBlob)...)
	out = append(out, sshString(section)...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}), true
}

// sshString is the SSH wire encoding of a length-prefixed string.
func sshString(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func (c *converter) attach(e *kp.Entry, d document) {
	// KeePassXC's importer reads "<id>__<name>" but the 1Password docs show
	// three underscores, so fall back to any "<id>_...<name>" entry.
	path := "files/" + d.DocumentID + "__" + d.FileName
	data, err := c.readFile(path)
	if err != nil {
		for _, f := range c.zip.File {
			if strings.HasPrefix(f.Name, "files/"+d.DocumentID+"_") && strings.HasSuffix(f.Name, "_"+d.FileName) {
				path = f.Name
				data, err = c.readFile(path)
				break
			}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s: missing attachment %s\n", e.GetTitle(), path)
		return
	}
	c.attachBytes(e, d.FileName, data)
}

func (c *converter) attachBytes(e *kp.Entry, fileName string, data []byte) {
	if len(data) == 0 {
		return
	}
	bin := c.db.AddBinary(data)
	e.Binaries = append(e.Binaries, bin.CreateReference(fileName))
	c.stats.attachments++
}

func (c *converter) readFile(path string) ([]byte, error) {
	for _, f := range c.zip.File {
		if f.Name == path {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("%s not found in archive", path)
}

// set adds a string attribute, skipping empty values so the entry stays clean.
func set(e *kp.Entry, key, value string, protected bool) {
	if value == "" {
		return
	}
	v := kp.V{Content: value}
	if protected {
		v.Protected = w.NewBoolWrapper(true)
	}
	// KeePassXC rejects a database with repeated keys, and 1Password allows
	// several fields with the same title, so suffix later ones.
	base := key
	for i := 2; e.Get(key) != nil; i++ {
		key = fmt.Sprintf("%s_%d", base, i)
	}
	e.Values = append(e.Values, kp.ValueData{Key: key, Value: v})
}

// str decodes a JSON scalar to text; non-scalars yield "" and are dropped.
func str(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// times builds TimeData purely from export timestamps. gokeepasslib stamps
// "now" by default, which makes identical exports differ and KeePassXC then
// reports false merge conflicts.
func times(created, updated int64) kp.TimeData {
	td := kp.NewTimeData()
	c, u := unix(created), unix(updated)
	td.CreationTime, td.LastModificationTime, td.LastAccessTime = c, u, u
	td.ExpiryTime, td.LocationChanged = c, c
	return td
}

func unix(sec int64) *w.TimeWrapper {
	return &w.TimeWrapper{Time: time.Unix(sec, 0).UTC()}
}

// stableUUID returns a name-based (version 5) UUID so that the same 1Password
// object always maps to the same KeePass UUID. That is what lets
// `keepassxc-cli merge` match entries across exports.
func stableUUID(name string) kp.UUID {
	const namespace = "1pux2kdbx/"
	sum := sha1.Sum([]byte(namespace + name))
	var u kp.UUID
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return u
}
