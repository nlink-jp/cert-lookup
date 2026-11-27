package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/nlink-jp/mcp"
	"github.com/nlink-jp/mcp/client"
)

// openMCP runs the whole mcp subcommand over pipes and opens it with
// nlink-jp/mcp's client, the way a dual-era client does (server-migration
// §6). The subcommand must exit 0 once the client closes.
func openMCP(t *testing.T) *client.Client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errOut bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"mcp"}, "t", inR, outW, &errOut)
		_ = outW.Close()
	}()
	kill := func() { _ = inW.Close(); _ = outR.Close() }
	conn, err := client.NewLineConn(outR, inW, kill, client.LineOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := client.Open(ctx, conn, client.Options{Client: mcp.Implementation{Name: "test", Version: "0"}})
	if err != nil {
		kill()
		t.Fatalf("open: %v (stderr %s)", err, errOut.String())
	}
	t.Cleanup(func() {
		_ = cl.Close()
		select {
		case code := <-done:
			if code != exitOK {
				t.Errorf("mcp exit = %d, stderr = %s", code, errOut.String())
			}
		case <-time.After(5 * time.Second):
			t.Error("the mcp subcommand did not end after the client closed")
		}
		kill()
	})
	return cl
}

// callMCP calls one tool and returns its first text block and isError.
func callMCP(t *testing.T, cl *client.Client, tool string, args any) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cl.CallTool(ctx, tool, args, nil)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var block struct{ Text string }
	if len(res.Content) == 0 || json.Unmarshal(res.Content[0], &block) != nil {
		t.Fatalf("%s: content = %v", tool, res.Content)
	}
	return block.Text, res.IsError
}
