package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "1pux2kdbx")
	if out, err := exec.Command("go", "build", "-ldflags", "-X main.version=v9.9.9", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// runCLI returns stderr and the exit code.
func runCLI(t *testing.T, bin, password string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "KDBX_PASSWORD="+password)
	cmd.Stdin = strings.NewReader("")
	var stderr, stdout bytes.Buffer
	cmd.Stderr, cmd.Stdout = &stderr, &stdout
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String() + stderr.String(), code
}

func TestCLI(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	in, out := filepath.Join(dir, "a.1pux"), filepath.Join(dir, "a.kdbx")
	baseExport(t, in, "p", 1700000000)

	t.Run("version", func(t *testing.T) {
		got, code := runCLI(t, bin, "", "-version")
		if code != 0 || strings.TrimSpace(got) != "v9.9.9" {
			t.Errorf("got %q exit %d", got, code)
		}
	})

	t.Run("missing flags", func(t *testing.T) {
		if _, code := runCLI(t, bin, testPassword); code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})

	t.Run("bad input", func(t *testing.T) {
		got, code := runCLI(t, bin, testPassword, "-in", filepath.Join(dir, "missing"), "-out", out)
		if code != 1 || !strings.Contains(got, "error:") {
			t.Errorf("got %q exit %d", got, code)
		}
	})

	t.Run("no password and no terminal", func(t *testing.T) {
		got, code := runCLI(t, bin, "", "-in", in, "-out", out)
		if code != 1 || !strings.Contains(got, "read password") {
			t.Errorf("got %q exit %d", got, code)
		}
	})

	t.Run("convert", func(t *testing.T) {
		got, code := runCLI(t, bin, testPassword, "-in", in, "-out", out, "-name", "My Backup")
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, got)
		}
		if !strings.Contains(got, "2 groups, 5 entries, 2 attachments, 0 skipped") {
			t.Errorf("stats line = %q", got)
		}
		if db, _ := open(t, out); db.Content.Meta.DatabaseName != "My Backup" {
			t.Errorf("database name = %q", db.Content.Meta.DatabaseName)
		}
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
			}
		}
	})
}
