package mcp

import (
	"encoding/json"
	"io"

	"github.com/nlink-jp/cert-lookup/internal/config"
	"github.com/nlink-jp/cert-lookup/internal/engine"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

// defaultProtocolVersion is advertised when the client sends none.
const defaultProtocolVersion = "2025-06-18"

// serverName is what initialize reports, and what a client lists the server as.
const serverName = "cert-lookup"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // absent/null ⇒ notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolResult is the tools/call payload.
type toolResult struct {
	Content []contentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(isErr bool, text string) toolResult {
	return toolResult{Content: []contentItem{{Type: "text", Text: text}}, IsError: isErr}
}

// Looker is the part of the engine the tools call, so tests can stand in.
type Looker interface {
	Lookup(domains []string, o engine.Options) (*engine.Report, error)
	Allowances() map[string]engine.Observed
}

// Options are the server's dependencies. Engine is the same engine the CLI
// uses, so MCP and CLI behaviour cannot diverge. ValidinQuota reads Validin's
// remaining queries (it spends none); nil when Validin has no key.
type Options struct {
	Config       *config.Config
	Engine       Looker
	ValidinQuota func() (*validin.Remaining, error)
	Version      string
}

type server struct {
	cfg     *config.Config
	eng     Looker
	quota   func() (*validin.Remaining, error)
	version string
}

// Serve runs the MCP protocol loop until in reaches EOF, which is the shutdown
// signal. It is safe to point in at os.Stdin and out at os.Stdout; diagnostics
// must go to stderr only.
func Serve(o Options, in io.Reader, out io.Writer) error {
	s := &server{cfg: o.Config, eng: o.Engine, quota: o.ValidinQuota, version: o.Version}
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			// The stream position is unrecoverable after malformed JSON;
			// report a parse error and stop rather than spin on the same bytes.
			_ = enc.Encode(response{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			return nil
		}
		resp, skip := s.handle(&req)
		if skip {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
}

func (s *server) handle(req *request) (response, bool) {
	// A missing or null id marks a JSON-RPC notification: never reply.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return response{}, true
	}
	switch req.Method {
	case "initialize":
		return s.ok(req.ID, s.initializeResult(req.Params)), false
	case "ping":
		return s.ok(req.ID, struct{}{}), false
	case "tools/list":
		return s.ok(req.ID, toolsList()), false
	case "tools/call":
		res, rerr := s.toolsCall(req.Params)
		if rerr != nil {
			return response{JSONRPC: "2.0", ID: req.ID, Error: rerr}, false
		}
		return s.ok(req.ID, res), false
	default:
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}}, false
	}
}

func (s *server) ok(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *server) initializeResult(params json.RawMessage) any {
	pv := defaultProtocolVersion
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
			pv = p.ProtocolVersion
		}
	}
	return map[string]any{
		"protocolVersion": pv,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": serverName, "version": s.version},
		"instructions":    Instructions,
	}
}
