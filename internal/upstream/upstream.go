// Package upstream holds what both API clients share: the error type the engine
// sorts failures by, and a bounded body read.
//
// Upstream error text is never passed through. SSLMate's bad_credentials
// message quotes the leading part of the key that was sent (measured in Phase
// 0), and Validin's error body is free text; every message here is our own,
// built from the HTTP status and, at most, upstream's machine-readable code.
package upstream

import (
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/cert-lookup/internal/guard"
)

// Error codes the engine and the MCP layer report (RFP §2).
const (
	CodeInvalidAPIKey = "invalid_api_key"
	CodeRateLimited   = "rate_limited"
	CodeTimeout       = "timeout"
	CodeUpstream      = "upstream_error"
)

// Error is a failed request to one source.
type Error struct {
	Source string // "SSLMate" or "Validin"
	Code   string // one of the Code constants
	Status int    // HTTP status, 0 when the request never got one
	// UpstreamCode is the source's own machine-readable code when it sent one
	// (SSLMate's "rate_limited", "bad_credentials" ...), cleaned and capped.
	UpstreamCode string
	// RetryAfter is the source's Retry-After in seconds, 0 when absent.
	RetryAfter int
	Detail     string // our own words
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", e.Source, e.Detail)
	if e.Status != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.Status)
		if e.UpstreamCode != "" {
			fmt.Fprintf(&b, ", %s", e.UpstreamCode)
		}
		b.WriteString(")")
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, "; retry after %d seconds", e.RetryAfter)
	}
	return b.String()
}

// MachineCode cleans an upstream code for display: a short token of letters,
// digits and underscores, or nothing.
func MachineCode(s string) string {
	s = guard.Cap(s, 40)
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return ""
		}
	}
	return s
}

// MaxBody bounds every response read. One SSLMate page with names expanded
// measured 540-608 KB (google.com, Phase 0); Validin's largest measured answer
// was 643 KB.
const MaxBody = 16 << 20

// ReadBody reads a response body up to MaxBody and refuses anything longer, so a
// misbehaving upstream cannot exhaust memory and a cut body is never parsed as
// if whole.
func ReadBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBody {
		return nil, fmt.Errorf("response larger than %d bytes", MaxBody)
	}
	return b, nil
}
