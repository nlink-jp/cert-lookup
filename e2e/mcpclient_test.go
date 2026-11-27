//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/nlink-jp/mcp"
	"github.com/nlink-jp/mcp/client"
)

// callBinary starts `bin mcp` with env, opens it with nlink-jp/mcp's client
// the way a dual-era client does (ADR-030 §6), calls one tool, and returns
// its first text block and isError. The binary must exit 0 once the client
// closes.
func callBinary(t *testing.T, bin string, env []string, tool string, args any) (string, bool) {
	t.Helper()
	cmd := exec.Command(bin, "mcp")
	cmd.Env = env
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := client.NewLineConn(stdout, stdin, func() { _ = stdin.Close() }, client.LineOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl, err := client.Open(ctx, conn, client.Options{Client: mcp.Implementation{Name: "e2e", Version: "0"}})
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("open: %v (stderr %q)", err, errOut.String())
	}
	res, callErr := cl.CallTool(ctx, tool, args, nil)
	_ = cl.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("mcp exited with %v (stderr %q)", err, errOut.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Error("mcp did not exit after the client closed")
	}
	if callErr != nil {
		t.Fatalf("%s: %v", tool, callErr)
	}
	var block struct{ Text string }
	if len(res.Content) == 0 || json.Unmarshal(res.Content[0], &block) != nil {
		t.Fatalf("%s: content = %v", tool, res.Content)
	}
	return block.Text, res.IsError
}
