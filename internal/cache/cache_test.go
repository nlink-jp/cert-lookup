package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPutGetRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	want := json.RawMessage(`{"revoked":true,"issuer":{"name":"Example<CA>"}}`)

	if err := s.Put("k.json", want, now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get("k.json", now.Add(time.Minute), time.Hour)
	if !ok {
		t.Fatal("Get: miss on a fresh entry")
	}
	if string(got) != string(want) {
		t.Errorf("Get = %s, want %s", got, want)
	}
}

// The TTL is applied when reading, so lowering it in the config expires entries
// that are already on disk — and which TTL an entry ages on is the caller's
// choice, not something stored with it.
func TestTTLAppliedAtReadTime(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	if err := s.Put("k.json", json.RawMessage(`1`), now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get("k.json", now.Add(90*time.Minute), 2*time.Hour); !ok {
		t.Error("entry should still be fresh under a 2h TTL")
	}
	if _, ok := s.Get("k.json", now.Add(90*time.Minute), time.Hour); ok {
		t.Error("entry should have expired under a 1h TTL")
	}
}

func TestMissesAreNotErrors(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, ok := s.Get("absent.json", time.Now(), time.Hour); ok {
		t.Error("Get reported a hit for a file that does not exist")
	}
}

// A truncated or hand-edited entry must read as a miss, not crash the lookup.
func TestCorruptEntryReadsAsMiss(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "k.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := s.Get("k.json", time.Now(), time.Hour); ok {
		t.Error("corrupt entry reported as a hit")
	}
	// And it must be overwritable.
	if err := s.Put("k.json", json.RawMessage(`2`), time.Now()); err != nil {
		t.Errorf("Put over a corrupt entry: %v", err)
	}
}

func TestKeyVariesWithEveryPart(t *testing.T) {
	base := Key("host", "8.8.8.8", "full")
	variants := map[string]string{
		"different kind":  Key("count", "8.8.8.8", "full"),
		"different value": Key("host", "1.1.1.1", "full"),
		"different view":  Key("host", "8.8.8.8", "minify"),
		"case kept":       Key("search", "Apache"),
	}
	if variants["case kept"] == Key("search", "apache") {
		t.Error("a query's case was folded into the key")
	}
	for name, got := range variants {
		if got == base {
			t.Errorf("%s produced the same key %q", name, got)
		}
	}
}

// Parts are length-prefixed, so lists that join to the same string stay apart.
func TestKeyPartsCannotCollideByJoining(t *testing.T) {
	pairs := [][2][]string{
		{{"a_b", "c"}, {"a", "b_c"}},
		{{"ab", ""}, {"a", "b"}},
		{{"x|y"}, {"x", "y"}},
		{{"1:a|"}, {"1:a|", ""}},
	}
	for _, p := range pairs {
		if Key("search", p[0]...) == Key("search", p[1]...) {
			t.Errorf("%q and %q share a key", p[0], p[1])
		}
	}
}

// What was investigated never appears in a filename, and a bad kind cannot
// become a path.
func TestKeyKeepsInputsOutOfTheFilename(t *testing.T) {
	k := Key("host", "203.0.113.7", "https://example.test/a?b=c")
	if strings.Contains(k, "203.0.113.7") || strings.ContainsAny(k, "/:?&") {
		t.Errorf("key exposes its input or unsafe characters: %q", k)
	}
	if !strings.HasPrefix(k, "host_") || !strings.HasSuffix(k, ".json") || len(k) > 64 {
		t.Errorf("unexpected key shape: %q", k)
	}
	for _, kind := range []string{"../etc", "Host", "", "a-very-long-kind-label"} {
		if got := Key(kind, "x"); !strings.HasPrefix(got, "entry_") {
			t.Errorf("kind %q was used in the filename: %q", kind, got)
		}
	}
}

// A TTL of 0 is how the config turns caching off for a kind: always a miss,
// even for an entry written a moment ago.
func TestAZeroTTLIsAlwaysAMiss(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	if err := s.Put("k.json", json.RawMessage(`1`), now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get("k.json", now, 0); ok {
		t.Error("a zero TTL returned a hit")
	}
}

func TestStatAndClear(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	now := time.Unix(1_700_000_000, 0)

	if got := s.Stat(); got.Entries != 0 {
		t.Errorf("empty cache reports %d entries", got.Entries)
	}
	for _, k := range []string{"a.json", "b.json", "c.json"} {
		if err := s.Put(k, json.RawMessage(`{"x":1}`), now); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	// A non-cache file in the directory must not be counted or removed.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	st := s.Stat()
	if st.Entries != 3 {
		t.Errorf("Entries = %d, want 3", st.Entries)
	}
	if st.Bytes == 0 {
		t.Error("Bytes = 0 for a non-empty cache")
	}
	if st.Dir != dir {
		t.Errorf("Dir = %q, want %q", st.Dir, dir)
	}

	n, err := s.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n != 3 {
		t.Errorf("Clear removed %d, want 3", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Error("Clear removed a file it does not own")
	}
}

func TestClearOnMissingDirIsNotAnError(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "never-created")}
	n, err := s.Clear()
	if err != nil {
		t.Errorf("Clear on a missing directory: %v", err)
	}
	if n != 0 {
		t.Errorf("Clear removed %d entries from a missing directory", n)
	}
}

// A crash mid-write must not leave a half-written entry that later reads as a
// valid but truncated result, so writes go through a temp file and a rename.
func TestPutLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	if err := s.Put("k.json", json.RawMessage(`{"x":1}`), time.Now()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("Put left a temp file behind: %s", e.Name())
		}
	}
}

// A hit returns the bytes that were put. encoding/json would otherwise escape
// < > & on the way in, and anything hashing the body would see it change.
func TestAHitIsTheBytesThatWerePut(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	want := json.RawMessage(`{"html":"<b>a & b</b>"}`)
	if err := s.Put("k.json", want, now); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get("k.json", now, time.Hour)
	if !ok || string(got) != string(want) {
		t.Errorf("Get = %s, want %s", got, want)
	}
}

func TestLoadReturnsTheFetchTimeWithoutJudging(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	then := time.Unix(1_700_000_000, 0)
	if err := s.Put("k.json", json.RawMessage(`{"a":1}`), then); err != nil {
		t.Fatal(err)
	}
	raw, at, ok := s.Load("k.json")
	if !ok || !at.Equal(then) || string(raw) != `{"a":1}` {
		t.Fatalf("Load = %s, %v, %v", raw, at, ok)
	}
	if _, _, ok := s.Load("absent.json"); ok {
		t.Fatal("a missing entry must be a miss")
	}
}

func TestCacheDirIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c")
	s := &Store{Dir: dir}
	if err := s.Put("k.json", json.RawMessage(`1`), time.Now()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("cache dir mode = %04o, want 0700", perm)
	}
}

func TestClearRemovesLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	if err := s.Put("k.json", json.RawMessage(`1`), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte(`{"half":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Clear(); err != nil || n != 2 {
		t.Fatalf("Clear = %d, %v; want the entry and the temp file", n, err)
	}
}
