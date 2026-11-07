package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// A fixture for "upstream sends an escape sequence" is written with an escape,
// never with the character itself. Three times a toolchain between the author
// and the file turned a typed backslash-u into the raw character: once that
// made a JSON fixture invalid and its test pass vacuously, and once it put a
// raw right-to-left override into a test of right-to-left overrides. A raw
// control or bidirectional character in a source file is also what a
// "Trojan Source" change looks like, so none is allowed in at all.
func TestSourcesHoldNoRawControlOrBidiCharacters(t *testing.T) {
	checked := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".md", ".toml", ".yml", ".yaml", ".sh", ".mod", ".tmpl", ".mk":
		default:
			if d.Name() != "Makefile" && d.Name() != "LICENSE" {
				return nil
			}
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		if !utf8.Valid(body) {
			t.Errorf("%s is not valid UTF-8", path)
			return nil
		}
		for n, line := range strings.Split(string(body), "\n") {
			for _, r := range line {
				if r == '\t' || (r == '\r' && strings.HasSuffix(line, "\r")) {
					continue
				}
				if forbidden(r) {
					t.Errorf("%s:%d holds a raw U+%04X; write it as an escape", path, n+1, r)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Fatalf("only %d files were checked; the walk is not seeing the tree", checked)
	}
}

func forbidden(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f: // C0, DEL, C1
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi embeddings, overrides, isolates
	case r == 0x200e, r == 0x200f, r == 0x061c: // LRM, RLM, ALM
	case r == 0xfffd, r == 0xfeff: // a replacement character is a decoding accident; a BOM is invisible
	default:
		return false
	}
	return true
}
