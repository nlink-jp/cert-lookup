package mcp

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nlink-jp/cert-lookup/internal/engine"
	"github.com/nlink-jp/cert-lookup/internal/issuance"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
)

// The manual is what an agent reads before its first call; these tests pin it
// to the code so that it cannot drift from the real tool set.

type listedTool struct {
	Name        string `json:"name"`
	InputSchema struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	} `json:"inputSchema"`
}

func listed(t *testing.T) []listedTool {
	t.Helper()
	b, err := json.Marshal(toolsList())
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Tools []listedTool `json:"tools"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Tools) == 0 {
		t.Fatal("toolsList advertises nothing")
	}
	return l.Tools
}

func TestUsageMentionsEveryToolAndArgument(t *testing.T) {
	for _, tl := range listed(t) {
		if !strings.Contains(usageMarkdown, "`"+tl.Name+"`") {
			t.Errorf("usage.md never mentions the tool `%s`", tl.Name)
		}
		for arg := range tl.InputSchema.Properties {
			if !strings.Contains(usageMarkdown, "`"+arg+"`") {
				t.Errorf("usage.md never documents %s's %q argument", tl.Name, arg)
			}
		}
	}
}

// Every Tool* and Code* constant declared in this package must appear in the
// manual. Read from the source, so a new constant cannot slip past.
func TestUsageDocumentsEveryToolAndCodeConstant(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Tool") && !strings.HasPrefix(name.Name, "Code") {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Errorf("%s is not a string literal; the scan cannot read it", name.Name)
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				found++
				if !strings.Contains(usageMarkdown, "`"+v+"`") {
					t.Errorf("usage.md never mentions %s (`%s`)", name.Name, v)
				}
			}
			return true
		})
	}
	if found < 10 {
		t.Fatalf("only %d Tool*/Code* constants found; the scan is not seeing them", found)
	}
}

// The codes the engine and the clients produce reach the agent through this
// package's documented spellings; a rename on either side must fail here.
func TestCodesMatchTheirSources(t *testing.T) {
	for mcpCode, src := range map[string]string{
		CodeHistoryUnavailable: engine.CodeHistoryUnavailable,
		CodeQuotaExhausted:     engine.CodeQuotaExhausted,
		CodeInvalidAPIKey:      upstream.CodeInvalidAPIKey,
		CodeRateLimited:        upstream.CodeRateLimited,
		CodeTimeout:            upstream.CodeTimeout,
		CodeUpstream:           upstream.CodeUpstream,
	} {
		if mcpCode != src {
			t.Errorf("mcp spells %q, its source %q", mcpCode, src)
		}
	}
}

// Every value an agent must read in a result is documented.
func TestUsageDocumentsResultValues(t *testing.T) {
	for _, v := range []string{
		issuance.Revoked, issuance.NotRevoked, issuance.Unknown,
		issuance.SourceSSLMate, issuance.SourceValidin,
		engine.StateOK, engine.StateFailed, engine.StateNotRequested,
		engine.KindHost, engine.KindSubdomains,
		engine.TruncatedNewestMissing,
	} {
		if !strings.Contains(usageMarkdown, "`"+v+"`") && !strings.Contains(usageMarkdown, `"`+v+`"`) {
			t.Errorf("usage.md never documents %q", v)
		}
	}
	for _, field := range []string{"names_outside", "omitted", "omitted_total", "sample", "retry_after_seconds", "caa_domains", "seen_by", "degraded"} {
		if !strings.Contains(usageMarkdown, field) {
			t.Errorf("usage.md never mentions the field %q", field)
		}
	}
}

// org ADR-021 §10: every registered schema sets additionalProperties:false.
func TestEveryToolSchemaIsValidAndClosed(t *testing.T) {
	for _, tl := range listed(t) {
		if tl.InputSchema.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", tl.Name, tl.InputSchema.Type)
		}
		if tl.InputSchema.AdditionalProperties == nil || *tl.InputSchema.AdditionalProperties {
			t.Errorf("%s: schema should set additionalProperties:false", tl.Name)
		}
	}
}

// The instructions are the only text some clients surface.
func TestInstructionsCoverTheEssentials(t *testing.T) {
	for _, want := range []string{"get_usage", "lookup_certs", "history", "sample", "not evidence", "third-party", "punycode"} {
		if !strings.Contains(Instructions, want) {
			t.Errorf("Instructions should mention %q", want)
		}
	}
}
