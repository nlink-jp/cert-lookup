package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// record is the on-disk envelope. Storing the fetch time rather than an expiry
// lets a config TTL change apply to entries already written.
type record struct {
	FetchedAtUnix int64           `json:"fetched_at_unix"`
	Result        json.RawMessage `json:"result"`
}

// Store is a result cache rooted at a directory.
type Store struct {
	Dir string
}

// Stats describes the cache, for cache_status.
type Stats struct {
	Dir     string    `json:"dir"`
	Entries int       `json:"entries"`
	Bytes   int64     `json:"bytes"`
	Oldest  time.Time `json:"oldest,omitzero"`
	Newest  time.Time `json:"newest,omitzero"`
}

// Key names a cache entry: kind, a short readable label for the kind of
// answer ("sslmate", "validin"), and parts, every value that determines
// the answer. The parts are length-prefixed before hashing, so no two
// different part lists can collide — joining them with a separator could: the
// sibling cve-lookup served one product match's answer to another question
// whose parts joined to the same string. Case is kept.
//
// The parts never appear in the filename, only their hash: what was
// investigated (an IP, a query) does not sit readable in a directory listing.
// kind must be a short lower-case label; anything else is replaced, so a
// caller's mistake cannot reach the filesystem as a path.
func Key(kind string, parts ...string) string {
	if !safeName(kind) || len(kind) > 16 {
		kind = "entry"
	}
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s|", len(p), p)
	}
	return kind + "_" + hex.EncodeToString(h.Sum(nil)[:16]) + ".json"
}

func safeName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Load returns the cached raw result for key and when it was fetched, without
// judging freshness: an SSLMate answer ages by its content (an empty answer
// sooner than one with issuances), so the caller decides.
func (s *Store) Load(key string) (json.RawMessage, time.Time, bool) {
	b, err := os.ReadFile(filepath.Join(s.Dir, key))
	if err != nil {
		return nil, time.Time{}, false
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, time.Time{}, false // corrupt entries read as misses; Put overwrites them
	}
	return rec.Result, time.Unix(rec.FetchedAtUnix, 0), true
}

// Get returns the cached raw result for key when it was fetched within ttl of
// now. A ttl of 0 or less is always a miss: that is how the config turns a
// kind of answer's caching off.
func (s *Store) Get(key string, now time.Time, ttl time.Duration) (json.RawMessage, bool) {
	if ttl <= 0 {
		return nil, false // a TTL of 0 means this kind is not cached at all
	}
	b, err := os.ReadFile(filepath.Join(s.Dir, key))
	if err != nil {
		return nil, false
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, false // corrupt entries read as misses; Put overwrites them
	}
	if now.Sub(time.Unix(rec.FetchedAtUnix, 0)) > ttl {
		return nil, false
	}
	return rec.Result, true
}

// Put stores a raw result under key, stamped with the fetch time. The write is
// atomic (temp file + rename) so a crash never leaves a truncated entry.
//
// Callers must not Put a degraded result. Freezing an incomplete answer for the
// whole TTL would leave the analyst with no way to tell it apart from a
// complete one.
func (s *Store) Put(key string, result json.RawMessage, now time.Time) error {
	// 0700: the entries are investigation data (the addresses are hashed out
	// of the names, but the answers are about them).
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	// Encoded without HTML escaping: json.Marshal would rewrite < > & inside
	// the stored document as \u003c and friends, and a hit would no longer be
	// the bytes that were put.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(record{FetchedAtUnix: now.Unix(), Result: result}); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, key), bytes.TrimSpace(b.Bytes()))
}

// Stat describes the cache contents.
func (s *Store) Stat() Stats {
	st := Stats{Dir: s.Dir}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return st
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		st.Entries++
		st.Bytes += info.Size()
		mod := info.ModTime()
		if st.Oldest.IsZero() || mod.Before(st.Oldest) {
			st.Oldest = mod
		}
		if st.Newest.IsZero() || mod.After(st.Newest) {
			st.Newest = mod
		}
	}
	return st
}

// Clear removes every cached entry, returning the number removed.
func (s *Store) Clear() (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		// Entries, and temp files an interrupted write left behind (they hold
		// an answer too).
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".tmp-")) {
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
