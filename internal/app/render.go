package app

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/engine"
	"github.com/nlink-jp/cert-lookup/internal/issuance"
)

// namesPerLine is how many names the text view prints per issuance; the JSON
// keeps up to issuance.MaxNamesShown.
const namesPerLine = 6

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func renderText(w io.Writer, rep *engine.Report) {
	for i := range rep.Results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		renderDomain(w, &rep.Results[i])
	}
	if rem := rep.ValidinRemaining; rem != nil {
		fmt.Fprintf(w, "\nValidin queries left before this call: %d today, %d this month\n", rem.Daily, rem.Monthly)
	}
}

func renderDomain(w io.Writer, r *engine.DomainResult) {
	mode := "single host"
	if r.Subdomains {
		mode = "with subdomains"
	}
	sources := "SSLMate"
	if r.Sources.Validin.State != engine.StateNotRequested {
		sources += " + Validin history"
	}
	fmt.Fprintf(w, "%s  (%s; %s)\n", r.Domain, mode, sources)

	s := r.Summary
	line := fmt.Sprintf("  issuances: %d", s.Issuances)
	switch {
	case s.EarliestNotBefore != nil && s.LatestNotBefore != nil:
		line += fmt.Sprintf(" (earliest %s, latest %s)", day(*s.EarliestNotBefore), day(*s.LatestNotBefore))
	case s.EarliestNotBefore != nil:
		line += fmt.Sprintf(" (earliest %s; latest unknown — cut short)", day(*s.EarliestNotBefore))
	}
	fmt.Fprintln(w, line)
	if len(s.Issuers) > 0 {
		fmt.Fprintf(w, "  CAs: %s%s\n", strings.Join(s.Issuers, ", "), more(s.IssuersTotal, len(s.Issuers)))
	}
	if s.NamesOutsideTotal > 0 {
		fmt.Fprintf(w, "  names outside %s: %s%s\n", r.Domain, strings.Join(firstN(s.NamesOutside, 10), ", "), more(s.NamesOutsideTotal, min(10, len(s.NamesOutside))))
	}
	for _, is := range r.Issuances {
		renderIssuance(w, is)
	}
	if h := r.History; h != nil {
		span := ""
		if h.ObservedFrom != nil && h.ObservedTo != nil {
			span = fmt.Sprintf(", observed %s..%s", day(*h.ObservedFrom), day(*h.ObservedTo))
		}
		fmt.Fprintf(w, "  Validin history: %d records%s (a sample)\n", h.Records, span)
	}
	if r.Omitted > 0 {
		fmt.Fprintf(w, "  (%d older issuances omitted)\n", r.Omitted)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

func renderIssuance(w io.Writer, is issuance.Issuance) {
	state := is.Revocation.Status
	switch {
	case is.Expired && state == issuance.Unknown:
		state = "expired"
	case is.Expired:
		state = "expired, " + state
	case state == issuance.Revoked && is.Revocation.Time != nil:
		state = "REVOKED " + day(*is.Revocation.Time)
	case state == issuance.Revoked:
		state = "REVOKED"
	case state == issuance.Unknown:
		state = "revocation unknown"
	}
	name := is.Issuer.Name
	if name == "" {
		name = "(issuer unknown)"
	}
	fmt.Fprintf(w, "  - %s → %s  %s  %s  [%s]\n", day(is.NotBefore), day(is.NotAfter), name, state, strings.Join(is.SeenBy, "+"))
	fmt.Fprintf(w, "      %s%s\n", strings.Join(firstN(is.Names, namesPerLine), ", "), more(is.NamesTotal, min(namesPerLine, len(is.Names))))
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func more(total, shown int) string {
	if total > shown {
		return fmt.Sprintf(" (+%d more)", total-shown)
	}
	return ""
}
