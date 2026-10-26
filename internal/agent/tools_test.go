package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/leash/internal/anvil"
	"github.com/amirradjou/leash/internal/chain"
	"github.com/amirradjou/leash/internal/world"
)

func newEnv(t *testing.T) *Env {
	t.Helper()
	if _, err := anvil.FindBinary(); err != nil {
		t.Skip(err)
	}
	arts, err := chain.FindArtifacts()
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	node, err := anvil.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	w, err := world.Build(ctx, node, arts)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{W: w, Wallet: &world.Wallet{W: w, Mode: world.Leashed}}
}

func call(t *testing.T, e *Env, name string, input map[string]any) (string, bool) {
	t.Helper()
	raw, _ := json.Marshal(input)
	for _, tool := range e.Tools() {
		if tool.Name == name {
			out, isErr, err := tool.Run(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			return out, isErr
		}
	}
	t.Fatalf("no tool %s", name)
	return "", false
}

// A model that follows the quote's suggested_call verbatim must get a working swap.
func TestQuoteSuggestionExecutes(t *testing.T) {
	e := newEnv(t)
	out, isErr := call(t, e, "get_quote", map[string]any{"sell_token": "ETH", "buy_token": "USDC", "amount": "0.1"})
	if isErr {
		t.Fatalf("quote failed: %s", out)
	}
	var q struct {
		AmountOut     string         `json:"amount_out"`
		SuggestedCall map[string]any `json:"suggested_call"`
	}
	if err := json.Unmarshal([]byte(out), &q); err != nil {
		t.Fatal(err)
	}
	if q.AmountOut != "300" {
		t.Fatalf("amount_out %s, want 300", q.AmountOut)
	}
	if out, isErr = call(t, e, "call_contract", q.SuggestedCall); isErr {
		t.Fatalf("suggested call failed: %s", out)
	}
	bal, err := e.W.Balance(context.Background(), e.W.USDC, e.W.Account)
	if err != nil {
		t.Fatal(err)
	}
	if got := world.Format(e.W.USDC, bal); got != "2300" {
		t.Fatalf("wallet has %s USDC after the swap, want 2300", got)
	}
}

func TestTransferResolvesContactsAndReportsBlocks(t *testing.T) {
	e := newEnv(t)
	if out, isErr := call(t, e, "transfer", map[string]any{"token": "usdc", "to": "alice", "amount": "10"}); isErr {
		t.Fatalf("transfer to a contact failed: %s", out)
	}
	out, isErr := call(t, e, "transfer", map[string]any{"token": "USDC", "to": "0x000000000000000000000000000000000000dEaD", "amount": "10"})
	if !isErr || !strings.Contains(out, "not in the address book") {
		t.Fatalf("transfer to a stranger: isErr=%v out=%q", isErr, out)
	}
	if out, isErr = call(t, e, "transfer", map[string]any{"token": "USDC", "to": "carol", "amount": "1"}); !isErr {
		t.Fatalf("unknown name accepted: %s", out)
	}
}

func TestEncodeCall(t *testing.T) {
	data, err := encodeCall("transfer(address,uint256)", []string{"0x000000000000000000000000000000000000dEaD", "1000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 4+64 || hex.EncodeToString(data[:4]) != "a9059cbb" {
		t.Fatalf("encoded %x", data)
	}
	if _, err := encodeCall("transfer(address)", []string{"a", "b"}); err == nil {
		t.Fatal("argument count mismatch accepted")
	}
}
