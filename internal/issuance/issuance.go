// Package issuance merges what the two sources return into one list of
// issuances, and summarizes it per domain (RFP §2 "Merging issuances").
//
// One issuance arrives in several shapes: SSLMate lists the same issuance
// under several ids, and Validin lists the precertificate and the certificate
// once per CT log that recorded them. The rules, in order:
//
//  1. SSLMate issuances with the same tbs_sha256 are one issuance (the API
//     reference: it uniquely identifies the issuance).
//  2. A Validin record whose fingerprint equals an SSLMate cert_sha256 is that
//     issuance (measured: they matched).
//  3. Anything else is matched on the issuer's C, O and CN, not_before,
//     not_after and the name set. Validin carries no serial number (measured),
//     so the RFC 5280 identity cannot be used; the issuer is part of the tuple,
//     which keeps an RSA and an ECDSA certificate issued together apart (they
//     came from different intermediates, measured on a public example).
//
// The package does no I/O and reads no clock: now is passed in.
package issuance

import (
	"sort"
	"strings"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/domain"
	"github.com/nlink-jp/cert-lookup/internal/guard"
	"github.com/nlink-jp/cert-lookup/internal/sslmate"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

// Revocation statuses.
const (
	Revoked    = "revoked"
	NotRevoked = "not_revoked"
	Unknown    = "unknown"
)

// Source names in SeenBy.
const (
	SourceSSLMate = "sslmate"
	SourceValidin = "validin"
)

// Caps on what one result shows (RFP §2, §3).
const (
	MaxNamesShown        = 100
	MaxIssuersShown      = 20
	MaxNamesOutsideShown = 100
)

// Issuer names the certificate authority.
type Issuer struct {
	Name string `json:"name,omitempty"` // SSLMate's curated name, else the DN's O, else its CN
	DN   string `json:"dn,omitempty"`
}

// Revocation is one shape for every case (RFP §2): Status is unknown when
// SSLMate does not know, and for every issuance SSLMate did not return.
type Revocation struct {
	Status    string     `json:"status"`
	Time      *time.Time `json:"time,omitempty"`
	Reason    *int       `json:"reason,omitempty"` // RFC 5280 reason code; CAs are not always accurate
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// Issuance is one merged issuance.
type Issuance struct {
	Names      []string   `json:"names"`
	NamesTotal int        `json:"names_total"`
	Issuer     Issuer     `json:"issuer"`
	NotBefore  time.Time  `json:"not_before"`
	NotAfter   time.Time  `json:"not_after"`
	Expired    bool       `json:"expired"`
	Revocation Revocation `json:"revocation"`
	CAADomains []string   `json:"caa_domains,omitempty"`
	CertSHA256 []string   `json:"cert_sha256"`
	TBSSHA256  string     `json:"tbs_sha256,omitempty"`
	LoggedAt   *time.Time `json:"logged_at,omitempty"`
	SeenBy     []string   `json:"seen_by"`
}

type group struct {
	is      Issuance
	names   map[string]bool
	certs   map[string]bool
	sslmate bool
	validin bool
}

// Merge combines both sources' answers. Names are kept whole here (merging and
// summaries need every one); Shown caps them for output. now decides Expired.
func Merge(ss []sslmate.Issuance, vs []validin.Record, now time.Time) []Issuance {
	var groups []*group
	byTBS := map[string]*group{}
	byCert := map[string]*group{}
	byTuple := map[string]*group{}

	for _, s := range ss {
		g := byTBS[s.TBSSHA256]
		if g == nil {
			g = &group{names: map[string]bool{}, certs: map[string]bool{}}
			g.is = Issuance{
				Issuer:     Issuer{Name: s.Issuer.FriendlyName, DN: s.Issuer.Name},
				NotBefore:  s.NotBefore,
				NotAfter:   s.NotAfter,
				TBSSHA256:  s.TBSSHA256,
				CAADomains: s.Issuer.CAADomains,
				Revocation: revocation(s),
			}
			if g.is.Issuer.Name == "" {
				g.is.Issuer.Name = displayName(ParseDN(s.Issuer.Name))
			}
			byTBS[s.TBSSHA256] = g
			groups = append(groups, g)
		}
		g.sslmate = true
		addAll(g.names, s.DNSNames)
		if s.CertSHA256 != "" {
			g.certs[s.CertSHA256] = true
			byCert[s.CertSHA256] = g
		}
		k := tuple(ParseDN(s.Issuer.Name), s.NotBefore, s.NotAfter, keys(g.names))
		if byTuple[k] == nil {
			byTuple[k] = g
		}
	}

	for _, v := range vs {
		names := map[string]bool{}
		addAll(names, v.Domains)
		if v.CommonName != "" {
			names[v.CommonName] = true
		}
		comp := DN{C: v.Issuer.C, O: v.Issuer.O, CN: v.Issuer.CN}
		k := tuple(comp, v.NotBefore, v.NotAfter, keys(names))
		g := byCert[v.FingerprintSHA256]
		if g == nil {
			g = byTuple[k]
		}
		if g == nil {
			g = &group{names: map[string]bool{}, certs: map[string]bool{}}
			g.is = Issuance{
				Issuer:     Issuer{Name: displayName(comp), DN: comp.String()},
				NotBefore:  v.NotBefore,
				NotAfter:   v.NotAfter,
				Revocation: Revocation{Status: Unknown},
			}
			byTuple[k] = g
			groups = append(groups, g)
		}
		g.validin = true
		addAll(g.names, keys(names))
		g.certs[v.FingerprintSHA256] = true
		byCert[v.FingerprintSHA256] = g
		at := v.LoggedAt
		if at.IsZero() {
			at = v.FirstSeen
		}
		if !at.IsZero() && (g.is.LoggedAt == nil || at.Before(*g.is.LoggedAt)) {
			t := at
			g.is.LoggedAt = &t
		}
	}

	out := make([]Issuance, 0, len(groups))
	for _, g := range groups {
		is := g.is
		is.Names = sortedNames(g.names)
		is.NamesTotal = len(is.Names)
		is.CertSHA256 = keys(g.certs)
		is.Expired = now.After(is.NotAfter)
		if g.sslmate {
			is.SeenBy = append(is.SeenBy, SourceSSLMate)
		}
		if g.validin {
			is.SeenBy = append(is.SeenBy, SourceValidin)
		}
		out = append(out, is)
	}
	// Newest first: the question is usually "what was issued lately".
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].NotBefore.Equal(out[j].NotBefore) {
			return out[i].NotBefore.After(out[j].NotBefore)
		}
		if !out[i].NotAfter.Equal(out[j].NotAfter) {
			return out[i].NotAfter.After(out[j].NotAfter)
		}
		return strings.Join(out[i].CertSHA256, ",") < strings.Join(out[j].CertSHA256, ",")
	})
	return out
}

// Shown returns a copy with at most MaxNamesShown names; NamesTotal keeps the
// full count.
func (is Issuance) Shown() Issuance {
	if len(is.Names) > MaxNamesShown {
		is.Names = append([]string(nil), is.Names[:MaxNamesShown]...)
	}
	return is
}

func revocation(s sslmate.Issuance) Revocation {
	r := Revocation{Status: Unknown}
	if s.Revoked != nil {
		r.Status = NotRevoked
		if *s.Revoked {
			r.Status = Revoked
		}
	}
	if s.Revocation != nil {
		r.Time, r.Reason, r.CheckedAt = s.Revocation.Time, s.Revocation.Reason, s.Revocation.CheckedAt
	}
	return r
}

// Summary is the per-domain overview (RFP §2).
type Summary struct {
	Issuances         int        `json:"issuances"`
	EarliestNotBefore *time.Time `json:"earliest_not_before,omitempty"`
	// LatestNotBefore is absent when SSLMate's walk was cut: the newest
	// issuances are the ones a cut loses (it returns oldest first).
	LatestNotBefore   *time.Time `json:"latest_not_before,omitempty"`
	Issuers           []string   `json:"issuers"`
	IssuersTotal      int        `json:"issuers_total"`
	NamesOutside      []string   `json:"names_outside"`
	NamesOutsideTotal int        `json:"names_outside_total"`
}

// Summarize builds the summary for queried domain d from every issuance (not
// only the ones a response budget lets through).
func Summarize(list []Issuance, d string, newestMissing bool) Summary {
	s := Summary{Issuances: len(list), Issuers: []string{}, NamesOutside: []string{}}
	seenIssuer := map[string]bool{}
	outside := map[string]bool{}
	for i := range list {
		is := &list[i]
		nb := is.NotBefore
		if s.EarliestNotBefore == nil || nb.Before(*s.EarliestNotBefore) {
			t := nb
			s.EarliestNotBefore = &t
		}
		if !newestMissing && (s.LatestNotBefore == nil || nb.After(*s.LatestNotBefore)) {
			t := nb
			s.LatestNotBefore = &t
		}
		if name := is.Issuer.Name; name != "" && !seenIssuer[name] {
			seenIssuer[name] = true
			s.IssuersTotal++
			if len(s.Issuers) < MaxIssuersShown {
				s.Issuers = append(s.Issuers, name)
			}
		}
		for _, n := range is.Names {
			if !domain.Inside(n, d) {
				outside[n] = true
			}
		}
	}
	all := sortedNames(outside)
	s.NamesOutsideTotal = len(all)
	if len(all) > MaxNamesOutsideShown {
		all = all[:MaxNamesOutsideShown]
	}
	s.NamesOutside = all
	return s
}

func tuple(dn DN, nb, na time.Time, names []string) string {
	return strings.Join([]string{
		strings.ToLower(dn.C), strings.ToLower(dn.O), strings.ToLower(dn.CN),
		nb.UTC().Format(time.RFC3339), na.UTC().Format(time.RFC3339),
		strings.Join(names, ","),
	}, "\x00")
}

func displayName(dn DN) string {
	switch {
	case dn.O != "":
		return dn.O
	default:
		return dn.CN
	}
}

func addAll(set map[string]bool, names []string) {
	for _, n := range names {
		if n != "" {
			set[n] = true
		}
	}
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNames(set map[string]bool) []string { return keys(set) }

// DN holds the issuer components the merge compares.
type DN struct{ C, O, CN string }

// String renders the components in SSLMate's style, for issuances only Validin
// saw.
func (d DN) String() string {
	var parts []string
	for _, p := range [][2]string{{"C", d.C}, {"O", d.O}, {"CN", d.CN}} {
		if p[1] != "" {
			parts = append(parts, p[0]+"="+escapeDN(p[1]))
		}
	}
	return strings.Join(parts, ", ")
}

func escapeDN(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `+`, `\+`, `"`, `\"`, `<`, `\<`, `>`, `\>`, `;`, `\;`)
	return r.Replace(v)
}

// ParseDN reads C, O and CN from an RFC 4514 / RFC 2253 distinguished name such
// as SSLMate's "C=US, O=Google Trust Services, CN=WE2". Escaped and quoted
// commas stay inside a value. When a type repeats, the last one wins. The
// values are cleaned and capped.
func ParseDN(s string) DN {
	var d DN
	for _, rdn := range splitRDNs(s) {
		typ, val, ok := strings.Cut(rdn, "=")
		if !ok {
			continue
		}
		val = guard.Text(unescapeDN(strings.TrimSpace(val)))
		switch strings.ToUpper(strings.TrimSpace(typ)) {
		case "C":
			d.C = val
		case "O":
			d.O = val
		case "CN":
			d.CN = val
		}
	}
	return d
}

func splitRDNs(s string) []string {
	var out []string
	var b strings.Builder
	escaped, quoted := false, false
	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune('\\')
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
			b.WriteRune(r)
		case (r == ',' || r == ';') && !quoted:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

func unescapeDN(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' || i+1 >= len(v) {
			b.WriteByte(c)
			continue
		}
		if i+2 < len(v) && isHex(v[i+1]) && isHex(v[i+2]) {
			b.WriteByte(hexVal(v[i+1])<<4 | hexVal(v[i+2]))
			i += 2
			continue
		}
		b.WriteByte(v[i+1])
		i++
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
