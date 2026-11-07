package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUnknownArgumentIsRefusedByName is the enforcing half of org ADR-021 §4:
// additionalProperties:false only tells a client what is allowed, and a client
// that does not check the schema sends the typo anyway. Every tool must refuse
// it, and the message must name the offending field.
func TestUnknownArgumentIsRefusedByName(t *testing.T) {
	for _, tc := range []struct{ tool, args, field string }{
		{ToolLookupCerts, `{"domains":["example.com"],"histroy":true}`, "histroy"},
		{ToolLookupCerts, `{"domain":"example.com"}`, "domain"},
		{ToolLookupCerts, `{"DOMAINS":["example.com"]}`, "DOMAINS"},
		{ToolLookupCerts, `{"domains":["example.com"],"History":true}`, "History"},
		{ToolCacheStatus, `{"verbose":true}`, "verbose"},
		{ToolGetUsage, `{"topic":"limits"}`, "topic"},
	} {
		t.Run(tc.tool+"/"+tc.field, func(t *testing.T) {
			eng := &fakeEngine{n: 1}
			text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("sk", ""), Engine: eng}, callTool(tc.tool, tc.args))[0])
			if !isErr {
				t.Fatalf("%s accepted unknown argument %q: %s", tc.tool, tc.field, text)
			}
			var e struct{ Code, Message string }
			if err := json.Unmarshal([]byte(text), &e); err != nil {
				t.Fatalf("tool error is not structured JSON: %v (%s)", err, text)
			}
			if e.Code != CodeInvalidInput || !strings.Contains(e.Message, `unknown field "`+tc.field+`"`) {
				t.Fatalf("got %+v; want invalid_input naming %q", e, tc.field)
			}
			if len(eng.calls) != 0 {
				t.Fatal("nothing may run before the arguments decode")
			}
		})
	}
}

// A malformed argument object is refused, not read as "no arguments".
func TestMalformedArgumentsAreRefused(t *testing.T) {
	text, isErr := toolText(t, serve(t, testConfig("", ""), callTool(ToolCacheStatus, `[1,2]`))[0])
	if !isErr || !strings.Contains(text, CodeInvalidInput) {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
}
