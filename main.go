// 1pux2kdbx converts a 1Password .1pux export into a KeePass .kdbx file whose
// entry and group UUIDs are derived from the 1Password IDs. Re-running it on a
// newer export produces a database that `keepassxc-cli merge` can reconcile
// with an earlier conversion instead of duplicating everything.
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"
)

func main() {
	in := flag.String("in", "", "path to the 1Password .1pux export")
	out := flag.String("out", "", "path of the .kdbx file to write")
	name := flag.String("name", "1Password Backup", "database name and root group name")
	flag.Parse()

	if *in == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}

	password, err := readPassword()
	if err != nil {
		fail(err)
	}

	stats, err := convert(*in, *out, *name, password)
	if err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d groups, %d entries, %d attachments, %d skipped\n",
		*out, stats.groups, stats.entries, stats.attachments, stats.skipped)
}

// readPassword takes the kdbx password from KDBX_PASSWORD, falling back to a
// no-echo terminal prompt.
func readPassword() (string, error) {
	if p := os.Getenv("KDBX_PASSWORD"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, "kdbx password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty password")
	}
	return string(b), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
