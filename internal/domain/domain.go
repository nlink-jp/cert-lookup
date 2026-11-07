// Package domain decides, before anything leaves the machine, whether an input
// is a DNS name cert-lookup may send (RFP §2 "Domain validation").
//
// Only ASCII is accepted. Internationalized names must arrive as punycode:
// converting Unicode correctly needs the IDNA mapping tables, which the
// standard library does not carry, and a homemade conversion that is subtly
// wrong would look up a different name than the one the analyst meant.
//
// Whether a name is registrable (as opposed to a public suffix such as co.jp)
// is not judged here. SSLMate answers a public suffix with an empty list
// rather than an error (measured in Phase 0), so the engine words an empty
// answer as "nothing held", never as "nothing issued".
package domain

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/nlink-jp/cert-lookup/internal/guard"
)

// Limits from RFC 1035.
const (
	MaxName  = 253
	MaxLabel = 63
)

// InvalidError says why an input was refused. Input is the operator's own
// text, cleaned and capped so a pasted control sequence cannot reach a terminal.
type InvalidError struct {
	Input  string
	Reason string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("%q is not a domain name cert-lookup can look up: %s", e.Input, e.Reason)
}

func invalid(raw, reason string) error {
	return &InvalidError{Input: guard.Cap(raw, 80), Reason: reason}
}

// Normalize returns the canonical form of one domain name: lower case, one
// trailing dot removed. Anything else that is not a plain DNS name is refused.
func Normalize(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", invalid(raw, "it is empty")
	}
	for _, r := range s {
		switch {
		case r > 0x7e:
			return "", invalid(raw, "it is not ASCII; pass an internationalized name as punycode (xn--...)")
		case r < 0x21 || r == 0x7f:
			return "", invalid(raw, "it holds whitespace or a control character")
		}
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/?#@:") {
		return "", invalid(raw, "pass the host name alone, not a URL (no scheme, path, port or user)")
	}
	if strings.Contains(s, "*") {
		return "", invalid(raw, "wildcards are not looked up; pass the domain (and --subdomains for its subtree)")
	}
	if _, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return "", invalid(raw, "it is an IP address; certificates are looked up by name")
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) > MaxName {
		return "", invalid(raw, fmt.Sprintf("it is longer than %d characters", MaxName))
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", invalid(raw, "it has a single label; pass a domain such as example.com")
	}
	for _, l := range labels {
		if reason := badLabel(l); reason != "" {
			return "", invalid(raw, reason)
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", invalid(raw, "its last label is all digits, which no top-level domain is")
	}
	return s, nil
}

func badLabel(l string) string {
	switch {
	case l == "":
		return "it has an empty label (two dots in a row, or a leading dot)"
	case len(l) > MaxLabel:
		return fmt.Sprintf("a label is longer than %d characters", MaxLabel)
	case l[0] == '-' || l[len(l)-1] == '-':
		return "a label starts or ends with a hyphen"
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Sprintf("it holds %q; a label is letters, digits and hyphens", string(c))
		}
	}
	return ""
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// ParseBatch validates every input and returns the distinct canonical names in
// input order. One bad input fails the whole batch, so a typo never half-runs a
// lookup and nothing is sent. More than max distinct names is refused, and so
// is a raw list longer than ten times max (a pasted log, not a lookup list).
func ParseBatch(raw []string, max int) ([]string, error) {
	if len(raw) > 10*max {
		return nil, &TooManyError{Count: len(raw), Max: max, Raw: true}
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range raw {
		d, err := Normalize(r)
		if err != nil {
			return nil, err
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) > max {
		return nil, &TooManyError{Count: len(out), Max: max}
	}
	return out, nil
}

// TooManyError says a batch holds more names than one call answers: more than
// Max distinct ones, or (Raw) more than ten times Max inputs in all.
type TooManyError struct {
	Count, Max int
	Raw        bool
}

func (e *TooManyError) Error() string {
	if e.Raw {
		return fmt.Sprintf("%d inputs given; at most %d distinct domain names per call", e.Count, e.Max)
	}
	return fmt.Sprintf("%d distinct domain names given; at most %d per call", e.Count, e.Max)
}

// Inside reports whether a certificate name belongs to the queried domain d:
// d itself, a name in d's subtree, or a wildcard that covers d or names in
// its subtree (*.example.com for d = www.example.com or example.com). Names
// that are not inside are the ones worth following to related domains
// (names_outside). Both must be lower case; d canonical.
func Inside(name, d string) bool {
	name = strings.ToLower(name)
	base, wildcard := strings.CutPrefix(name, "*.")
	if base == d || strings.HasSuffix(base, "."+d) {
		return true
	}
	if wildcard {
		if _, parent, ok := strings.Cut(d, "."); ok && base == parent {
			return true
		}
	}
	return false
}
