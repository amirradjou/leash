package world

import (
	"context"
	"flag"
	"math/big"
	"slices"
	"strconv"
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
	return newWorldOn(t, anvil.DefaultHardfork)
}

// newWorldOn is newWorld on a given hardfork.
func newWorldOn(t *testing.T, hardfork string) *World {
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
	node, err := anvil.StartHardfork(ctx, hardfork)
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

// TestGasPerOperation logs the gas table in docs/RESULTS.md: what one USDC transfer costs through each path, on
// prague and on osaka. On osaka the passkey's P-256 check runs in the EIP-7951 precompile instead of Solidity, so that
// path must be cheaper there.
func TestGasPerOperation(t *testing.T) {
	byFork := map[string][][]uint64{}
	for _, hf := range []string{"prague", "osaka"} {
		t.Run(hf, func(t *testing.T) { byFork[hf] = gasPerPath(t, newWorldOn(t, hf)) })
	}
	p, o := byFork["prague"], byFork["osaka"]
	if len(p) != 3 || len(o) != 3 {
		return // a subtest failed or was skipped
	}
	if pragueKey, osakaKey := p[2], o[2]; osakaKey[len(osakaKey)-1] >= pragueKey[0] {
		t.Errorf("passkey path should be cheaper with the P-256 precompile: prague %v, osaka %v", pragueKey, osakaKey)
	}
}

// gasRuns is how many operations are measured per path. Gas varies between operations (each one's signatures differ,
// and on prague the Solidity P-256 cost depends on the passkey signature), so the table gives median and range. The
// gas table in docs/RESULTS.md is: go test -run TestGasPerOperation -v ./internal/world -gas-runs=25
var gasRuns = flag.Int("gas-runs", 5, "operations measured per path in TestGasPerOperation")

// gasPerPath sends one warm-up transfer through each path, so a session's first write in a period is left out, then
// gasRuns more, and returns each path's gas sorted. Owner and session send 1 USDC to Alice so many runs stay under her
// daily limit; the passkey path sends Bob 200, over his.
func gasPerPath(t *testing.T, w *World) [][]uint64 {
	t.Helper()
	ctx := context.Background()
	if *gasRuns < 1 {
		t.Fatalf("-gas-runs must be at least 1, got %d", *gasRuns)
	}
	if err := w.Mint(ctx, w.USDC, w.Account, w.MustParse(w.USDC, strconv.Itoa((*gasRuns+1)*202))); err != nil {
		t.Fatal(err)
	}
	alice, bob := w.Contacts[0].Address, w.Contacts[1].Address
	paths := []struct {
		name     string
		wallet   *Wallet
		to       common.Address
		amount   string
		escalate bool
	}{
		{"owner (execute)", &Wallet{W: w, Mode: Unguarded}, alice, "1", false},
		{"session key", &Wallet{W: w, Mode: Leashed}, alice, "1", false},
		{"session key + passkey", &Wallet{W: w, Mode: Leashed}, bob, "200", true},
	}
	gas := make([][]uint64, len(paths))
	for i, p := range paths {
		for run := range *gasRuns + 1 {
			out, err := p.wallet.Execute(ctx, []Call{transferCall(t, w, w.USDC, p.to, p.amount)}, p.escalate)
			if err != nil {
				t.Fatal(err)
			}
			if !out.Executed {
				t.Fatalf("%s: blocked: %s", p.name, out.Blocked)
			}
			if run > 0 {
				gas[i] = append(gas[i], out.GasUsed)
			}
		}
		slices.Sort(gas[i])
		g := gas[i]
		t.Logf("%-22s median %7d  range %d-%d  (%d ops)", p.name, g[len(g)/2], g[0], g[len(g)-1], len(g))
	}
	if !(gas[0][len(gas[0])-1] < gas[1][0] && gas[1][len(gas[1])-1] < gas[2][0]) {
		t.Fatalf("expected owner < session < passkey, got %v", gas)
	}
	return gas
}
