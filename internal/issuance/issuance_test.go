package issuance

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/sslmate"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func hex64(c byte) string { return strings.Repeat(string(c), 64) }

var (
	now     = ts("2026-11-07T00:00:00Z")
	amazon  = "C=US, O=Amazon, CN=Amazon RSA 2048 M01"
	amazonV = validin.Issuer{C: "US", O: "Amazon", CN: "Amazon RSA 2048 M01"}
	f       = false
	tr      = true
)

// The shapes measured in Phase 0 for one domain: SSLMate lists the current
// issuance twice; Validin lists it as a certificate (fingerprint = cert_sha256)
// and a precertificate, plus an expired issuance SSLMate no longer returns, as
// a precertificate/certificate pair.
func phase0Shapes() ([]sslmate.Issuance, []validin.Record) {
	current := sslmate.Issuance{
		ID: "1", TBSSHA256: hex64('a'), CertSHA256: hex64('c'),
		DNSNames:  []string{"*.example.com", "example.com"},
		NotBefore: ts("2026-05-07T00:00:00Z"), NotAfter: ts("2026-11-20T23:59:59Z"),
		Revoked: &f, Issuer: sslmate.Issuer{FriendlyName: "Amazon Trust Services", Name: amazon, CAADomains: []string{"amazon.com"}},
	}
	dup := current
	dup.ID = "2"
	ss := []sslmate.Issuance{current, dup}
	vs := []validin.Record{
		{CommonName: "example.com", Domains: []string{"*.example.com"}, Issuer: amazonV, NotBefore: current.NotBefore, NotAfter: current.NotAfter, FingerprintSHA256: hex64('c'), LoggedAt: ts("2026-05-07T03:00:00Z")},
		{CommonName: "example.com", Domains: []string{"*.example.com"}, Issuer: amazonV, NotBefore: current.NotBefore, NotAfter: current.NotAfter, FingerprintSHA256: hex64('p'), Precert: true, LoggedAt: ts("2026-05-07T02:59:00Z")},
		{CommonName: "example.com", Domains: []string{"*.example.com", "example.net"}, Issuer: validin.Issuer{C: "US", O: "Amazon", CN: "Amazon RSA 2048 M02"}, NotBefore: ts("2024-06-20T00:00:00Z"), NotAfter: ts("2025-07-20T23:59:59Z"), FingerprintSHA256: hex64('d'), Precert: true},
		{CommonName: "example.com", Domains: []string{"*.example.com", "example.net"}, Issuer: validin.Issuer{C: "US", O: "Amazon", CN: "Amazon RSA 2048 M02"}, NotBefore: ts("2024-06-20T00:00:00Z"), NotAfter: ts("2025-07-20T23:59:59Z"), FingerprintSHA256: hex64('e'), FirstSeen: ts("2024-06-20T01:00:00Z")},
	}
	return ss, vs
}

func TestMergeFoldsEveryShapeOfOneIssuance(t *testing.T) {
	ss, vs := phase0Shapes()
	got := Merge(ss, vs, now)
	if len(got) != 2 {
		for _, g := range got {
			t.Logf("%+v", g)
		}
		t.Fatalf("got %d issuances; want 2 (current + expired)", len(got))
	}
	cur, old := got[0], got[1] // newest first
	if strings.Join(cur.SeenBy, ",") != "sslmate,validin" || cur.TBSSHA256 != hex64('a') {
		t.Fatalf("current = %+v", cur)
	}
	if strings.Join(cur.CertSHA256, ",") != hex64('c')+","+hex64('p') {
		t.Fatalf("current certs = %v; the precertificate joins by the tuple", cur.CertSHA256)
	}
	if cur.Issuer.Name != "Amazon Trust Services" || cur.Revocation.Status != NotRevoked || cur.Expired {
		t.Fatalf("current = %+v", cur)
	}
	if cur.LoggedAt == nil || !cur.LoggedAt.Equal(ts("2026-05-07T02:59:00Z")) {
		t.Fatalf("logged_at = %v; want the earliest observation", cur.LoggedAt)
	}
	if strings.Join(old.SeenBy, ",") != "validin" || len(old.CertSHA256) != 2 || !old.Expired {
		t.Fatalf("expired = %+v", old)
	}
	if old.Revocation.Status != Unknown || old.Issuer.Name != "Amazon" || old.Issuer.DN != "C=US, O=Amazon, CN=Amazon RSA 2048 M02" {
		t.Fatalf("Validin-only issuance = %+v", old)
	}
	if strings.Join(old.Names, ",") != "*.example.com,example.com,example.net" || old.NamesTotal != 3 {
		t.Fatalf("names = %v (CN joins the SAN list)", old.Names)
	}
}

// Measured on a public example: an RSA and an ECDSA certificate issued together
// carry the same names and validity but come from different intermediates.
func TestTwinsFromDifferentIntermediatesStayApart(t *testing.T) {
	nb, na := ts("2026-09-05T00:00:00Z"), ts("2026-12-04T00:00:00Z")
	names := []string{"*.example.com", "example.com"}
	vs := []validin.Record{
		{Domains: names, Issuer: validin.Issuer{C: "US", O: "Google Trust Services", CN: "WR1"}, NotBefore: nb, NotAfter: na, FingerprintSHA256: hex64('1')},
		{Domains: names, Issuer: validin.Issuer{C: "US", O: "Google Trust Services", CN: "WE1"}, NotBefore: nb, NotAfter: na, FingerprintSHA256: hex64('2')},
	}
	if got := Merge(nil, vs, now); len(got) != 2 {
		t.Fatalf("got %d; RSA and ECDSA twins must not merge", len(got))
	}
}

func TestRevocationShapes(t *testing.T) {
	when := ts("2026-08-01T00:00:00Z")
	reason := 4
	for name, c := range map[string]struct {
		revoked *bool
		rev     *sslmate.Revocation
		want    string
	}{
		"revoked":     {&tr, &sslmate.Revocation{Time: &when, Reason: &reason, CheckedAt: &when}, Revoked},
		"not revoked": {&f, nil, NotRevoked},
		"null":        {nil, nil, Unknown},
	} {
		t.Run(name, func(t *testing.T) {
			got := Merge([]sslmate.Issuance{{TBSSHA256: hex64('a'), Revoked: c.revoked, Revocation: c.rev, NotAfter: ts("2027-01-01T00:00:00Z")}}, nil, now)
			if got[0].Revocation.Status != c.want {
				t.Fatalf("status = %q, want %q", got[0].Revocation.Status, c.want)
			}
			if c.rev != nil && (got[0].Revocation.Reason == nil || *got[0].Revocation.Reason != 4 || got[0].Revocation.Time == nil) {
				t.Fatalf("revocation detail dropped: %+v", got[0].Revocation)
			}
		})
	}
}

func TestExpiredIsJudgedAtTheGivenTime(t *testing.T) {
	ss := []sslmate.Issuance{{TBSSHA256: hex64('a'), NotAfter: ts("2026-11-20T23:59:59Z")}}
	if Merge(ss, nil, ts("2026-11-20T23:59:59Z"))[0].Expired {
		t.Fatal("not expired at its last second")
	}
	if !Merge(ss, nil, ts("2026-11-21T00:00:00Z"))[0].Expired {
		t.Fatal("expired after not_after")
	}
}

func TestSummary(t *testing.T) {
	ss, vs := phase0Shapes()
	list := Merge(ss, vs, now)
	s := Summarize(list, "example.com", false)
	if s.Issuances != 2 || s.EarliestNotBefore == nil || s.LatestNotBefore == nil {
		t.Fatalf("summary = %+v", s)
	}
	if !s.EarliestNotBefore.Equal(ts("2024-06-20T00:00:00Z")) || !s.LatestNotBefore.Equal(ts("2026-05-07T00:00:00Z")) {
		t.Fatalf("range = %v .. %v", s.EarliestNotBefore, s.LatestNotBefore)
	}
	if strings.Join(s.Issuers, ",") != "Amazon Trust Services,Amazon" || s.IssuersTotal != 2 {
		t.Fatalf("issuers = %v", s.Issuers)
	}
	if strings.Join(s.NamesOutside, ",") != "example.net" || s.NamesOutsideTotal != 1 {
		t.Fatalf("names_outside = %v", s.NamesOutside)
	}
	if cut := Summarize(list, "example.com", true); cut.LatestNotBefore != nil {
		t.Fatal("a walk cut short loses the newest; the latest must not be reported")
	}
}

func TestSummaryAndShownAreCapped(t *testing.T) {
	var names []string
	for i := 0; i < 150; i++ {
		names = append(names, fmt.Sprintf("n%03d.other.example", i))
	}
	var ss []sslmate.Issuance
	for i := 0; i < 25; i++ {
		ss = append(ss, sslmate.Issuance{TBSSHA256: fmt.Sprintf("%064d", i), DNSNames: names, Issuer: sslmate.Issuer{FriendlyName: fmt.Sprintf("CA %02d", i)}, NotBefore: now.Add(time.Duration(i) * time.Hour), NotAfter: now.Add(48 * time.Hour)})
	}
	list := Merge(ss, nil, now)
	s := Summarize(list, "example.com", false)
	if len(s.Issuers) != MaxIssuersShown || s.IssuersTotal != 25 {
		t.Fatalf("issuers %d / %d", len(s.Issuers), s.IssuersTotal)
	}
	if len(s.NamesOutside) != MaxNamesOutsideShown || s.NamesOutsideTotal != 150 {
		t.Fatalf("names_outside %d / %d", len(s.NamesOutside), s.NamesOutsideTotal)
	}
	shown := list[0].Shown()
	if len(shown.Names) != MaxNamesShown || shown.NamesTotal != 150 || len(list[0].Names) != 150 {
		t.Fatalf("shown %d / total %d / original %d", len(shown.Names), shown.NamesTotal, len(list[0].Names))
	}
}

func TestParseDN(t *testing.T) {
	for in, want := range map[string]DN{
		"C=US, O=Google Trust Services, CN=WE2":                {C: "US", O: "Google Trust Services", CN: "WE2"},
		`C=GB, ST=Greater Manchester, O=Sectigo Limited, CN=X`: {C: "GB", O: "Sectigo Limited", CN: "X"},
		`C=US, O=Example\, Inc., CN=Example CA`:                {C: "US", O: "Example, Inc.", CN: "Example CA"},
		`C=US, O="Quoted, Inc.", CN=Q`:                         {C: "US", O: "Quoted, Inc.", CN: "Q"},
		`CN=Hex\41BC`:                                          {CN: "HexABC"},
		"":                                                     {},
		"cn=lower, o=case":                                     {O: "case", CN: "lower"},
		"O=Evil\u001b[2J":                                      {O: "Evil[2J"},
	} {
		if got := ParseDN(in); got != want {
			t.Errorf("ParseDN(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestDNStringRoundTrips(t *testing.T) {
	d := DN{C: "US", O: "Example, Inc.", CN: "CA+1"}
	if got := ParseDN(d.String()); got != d {
		t.Fatalf("ParseDN(%q) = %+v", d.String(), got)
	}
}
