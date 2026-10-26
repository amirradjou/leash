package world

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/amirradjou/leash/internal/anvil"
	"github.com/amirradjou/leash/internal/chain"
)

// newWorld starts Anvil and deploys a world, or skips when Anvil or the forge artifacts are missing.
func newWorld(t *testing.T) *World {
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
	w, err := Build(ctx, node, arts)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func transferCall(t *testing.T, w *World, tok Token, to common.Address, amount string) Call {
	t.Helper()
	v := w.MustParse(tok, amount)
	if tok.IsETH() {
		return Call{Target: to, Value: v}
	}
	data, err := w.ABI.ERC20.Pack("transfer", to, v)
	if err != nil {
		t.Fatal(err)
	}
	return Call{Target: tok.Address, Data: data}
}

func balance(t *testing.T, w *World, tok Token, who common.Address) string {
	t.Helper()
	v, err := w.Balance(context.Background(), tok, who)
	if err != nil {
		t.Fatal(err)
	}
	return Format(tok, v)
}

func TestSessionPaysWithinLimits(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	alice := w.Contacts[0].Address
	wallet := &Wallet{W: w, Mode: Leashed}

	out, err := wallet.Execute(ctx, []Call{transferCall(t, w, w.USDC, alice, "120")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Executed {
		t.Fatalf("transfer blocked: %s", out.Blocked)
	}
	if got := balance(t, w, w.USDC, alice); got != "120" {
		t.Fatalf("alice has %s USDC, want 120", got)
	}
	capLeft, cpLeft, err := w.SessionLimits(ctx, w.USDC, alice)
	if err != nil {
		t.Fatal(err)
	}
	if Format(w.USDC, capLeft) != "180" || Format(w.USDC, cpLeft) != "80" {
		t.Fatalf("limits left: cap %s, alice %s", Format(w.USDC, capLeft), Format(w.USDC, cpLeft))
	}
}

func TestPolicyBlocksAndExplains(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	attacker := chain.Addr(chain.Key("attacker"))
	wallet := &Wallet{W: w, Mode: Leashed}

	cases := []struct {
		name string
		call Call
		want string
	}{
		{"unknown recipient", transferCall(t, w, w.USDC, attacker, "50"), "not in the address book) may receive at most 0 USDC"},
		{"over counterparty limit", transferCall(t, w, w.USDC, w.Contacts[1].Address, "151"), "may receive at most 150 USDC"},
		{"over daily cap", transferCall(t, w, w.USDC, w.Contacts[0].Address, "301"), "daily USDC spending cap allows 300 USDC"},
		{"ETH to stranger", transferCall(t, w, ETH, attacker, "0.1"), "may receive at most 0 ETH"},
	}
	for _, c := range cases {
		out, err := wallet.Execute(ctx, []Call{c.call}, false)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if out.Executed || !strings.Contains(out.Blocked, c.want) {
			t.Errorf("%s: executed=%v blocked=%q, want %q", c.name, out.Executed, out.Blocked, c.want)
		}
	}
	if got := balance(t, w, w.USDC, attacker); got != "0" {
		t.Fatalf("attacker received %s USDC", got)
	}
}

func TestSwapOutputPinnedToAccount(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	wallet := &Wallet{W: w, Mode: Leashed}
	swap := func(to common.Address) Call {
		data, err := w.ABI.Swap.Pack("swapExactETHForTokens", big.NewInt(0), to)
		if err != nil {
			t.Fatal(err)
		}
		return Call{Target: w.Swap, Value: w.MustParse(ETH, "0.1"), Data: data}
	}

	out, err := wallet.Execute(ctx, []Call{swap(chain.Addr(chain.Key("attacker")))}, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Executed || !strings.Contains(out.Blocked, "must send their output to this wallet") {
		t.Fatalf("redirected swap: executed=%v blocked=%q", out.Executed, out.Blocked)
	}
	if out, err = wallet.Execute(ctx, []Call{swap(w.Account)}, false); err != nil || !out.Executed {
		t.Fatalf("swap to self: %v %+v", err, out)
	}
	if got := balance(t, w, w.USDC, w.Account); got != "2300" {
		t.Fatalf("account has %s USDC after swapping 0.1 ETH, want 2300", got)
	}
}

func TestPasskeyEscalation(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	bob := w.Contacts[1].Address
	wallet := &Wallet{W: w, Mode: Leashed}
	call := transferCall(t, w, w.USDC, bob, "900")

	if out, _ := wallet.Execute(ctx, []Call{call}, false); out.Executed {
		t.Fatal("over-limit transfer went through without the passkey")
	}
	out, err := wallet.Execute(ctx, []Call{call}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Executed {
		t.Fatalf("escalated transfer blocked: %s", out.Blocked)
	}
	if got := balance(t, w, w.USDC, bob); got != "900" {
		t.Fatalf("bob has %s USDC, want 900", got)
	}
}

func TestUnguardedWalletHasNoPolicy(t *testing.T) {
	w := newWorld(t)
	attacker := chain.Addr(chain.Key("attacker"))
	wallet := &Wallet{W: w, Mode: Unguarded}
	out, err := wallet.Execute(context.Background(), []Call{transferCall(t, w, w.USDC, attacker, "2000")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Executed {
		t.Fatalf("owner transfer blocked: %s", out.Blocked)
	}
	if got := balance(t, w, w.USDC, attacker); got != "2000" {
		t.Fatalf("attacker has %s USDC, want 2000", got)
	}
}
