package main

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
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
		Password           string    `json:"password"`
		NotesPlain         string    `json:"notesPlain"`
		Sections           []section `json:"sections"`
		DocumentAttributes *document `json:"documentAttributes"`
	} `json:"details"`
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

type sshKey struct {
	PrivateKey string            `json:"privateKey"`
	Metadata   map[string]string `json:"metadata"`
}

type stats struct{ groups, entries, attachments, skipped int }

// converter carries the open zip and the database being built so the
// per-item helpers stay small.
type converter struct {
	zip   *zip.ReadCloser
	db    *kp.Database
	stats stats
}

func convert(in, out, name, password string) (stats, error) {
	zr, err := zip.OpenReader(in)
	if err != nil {
		return stats{}, fmt.Errorf("open 1pux: %w", err)
	}
	defer zr.Close()

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

	root := kp.NewGroup()
	root.Name = name
	root.UUID = stableUUID("root")
	root.Times = times(0, 0)
	for _, acc := range ex.Accounts {
		for _, v := range acc.Vaults {
			root.Groups = append(root.Groups, c.group(v))
		}
	}

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
	defer f.Close()
	if err := kp.NewEncoder(f).Encode(c.db); err != nil {
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
		if it.State == "trashed" {
			c.stats.skipped++
			continue
		}
		g.Entries = append(g.Entries, c.entry(v.Attrs.UUID, it))
		c.stats.entries++
		if created == 0 || it.CreatedAt < created {
			created = it.CreatedAt
		}
		updated = max(updated, it.UpdatedAt)
	}
	g.Times = times(created, updated)
	return g
}

func (c *converter) entry(vaultID string, it item) kp.Entry {
	e := kp.NewEntry()
	// Item UUIDs are only unique within a vault, so scope them by vault.
	e.UUID = stableUUID(vaultID + ":" + it.UUID)

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
		c.attach(&e, d.FileName, "files/"+d.DocumentID+"__"+d.FileName)
	}

	e.Times = times(it.CreatedAt, it.UpdatedAt)
	return e
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
				c.attach(e, d.FileName, "files/"+d.DocumentID+"__"+d.FileName)
			}
		case "sshKey":
			var k sshKey
			if json.Unmarshal(raw, &k) == nil {
				c.attachBytes(e, "id_"+k.Metadata["keyType"], []byte(k.PrivateKey))
				set(e, "SSH Public Key", k.Metadata["publicKey"], false)
				set(e, "SSH Fingerprint", k.Metadata["fingerprint"], false)
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
			if json.Unmarshal(raw, &a) == nil {
				set(e, name, fmt.Sprintf("%s\n%s, %s %s\n%s",
					a["street"], a["city"], a["state"], a["zip"], a["country"]), false)
			}
		case "date", "monthYear":
			if n, err := strconv.ParseInt(string(raw), 10, 64); err == nil && n > 0 {
				set(e, name, unix(n).Time.Format("2006-01-02"), false)
			}
		default:
			set(e, name, str(raw), kind == "concealed")
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

func (c *converter) attach(e *kp.Entry, fileName, zipPath string) {
	data, err := c.readFile(zipPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s: missing attachment %s\n", e.GetTitle(), zipPath)
		return
	}
	c.attachBytes(e, fileName, data)
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
			defer rc.Close()
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
