package world

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/amirradjou/leash/internal/aa"
	"github.com/amirradjou/leash/internal/chain"
)

// Mode is how the agent's wallet is wired.
type Mode string

const (
	// Leashed: the agent holds a session key and every operation goes through the on-chain policy.
	Leashed Mode = "leash"
	// Unguarded: the agent holds the owner key, as if it ran a plain EOA wallet. The baseline for the eval.
	Unguarded Mode = "unguarded"
)

// Call is one call in a batch, as LeashAccount.Call.
type Call struct {
	Target common.Address
	Value  *big.Int
	Data   []byte
}

// Outcome of an operation the agent asked for.
type Outcome struct {
	Executed bool
	TxHash   common.Hash
	// Blocked is set when the policy (or the EntryPoint) refused the operation, in words the agent can act on.
	Blocked string
	// Reason is the raw revert, for logs.
	Reason string
}

// Wallet executes operations for the agent.
type Wallet struct {
	W    *World
	Mode Mode
}

// Execute runs a batch. With escalate, the passkey co-signs the operation (leashed mode only); callers must only set
// it after a human approved the specific operation.
func (wl *Wallet) Execute(ctx context.Context, calls []Call, escalate bool) (*Outcome, error) {
	w := wl.W
	for i := range calls {
		if calls[i].Value == nil {
			calls[i].Value = new(big.Int)
		}
	}
	var (
		callData []byte
		err      error
	)
	if wl.Mode == Leashed {
		callData, err = w.ABI.Account.Pack("executeAsSession", chain.Addr(w.Session), escalate, calls)
	} else {
		callData, err = w.ABI.Account.Pack("execute", calls)
	}
	if err != nil {
		return nil, err
	}
	op, err := w.Bundler.NewOp(ctx, w.Account, callData)
	if err != nil {
		return nil, err
	}
	hash, err := w.Bundler.Hash(ctx, op)
	if err != nil {
		return nil, err
	}
	if wl.Mode == Leashed {
		sig, err := ethSign(w.Session, hash)
		if err != nil {
			return nil, err
		}
		var auth []byte
		if escalate {
			assertion, err := w.Passkey.Sign(hash.Bytes())
			if err != nil {
				return nil, err
			}
			if auth, err = assertion.Encode(); err != nil {
				return nil, err
			}
		}
		if op.Signature, err = sessionSignatureArgs.Pack(sig, auth); err != nil {
			return nil, err
		}
	} else if op.Signature, err = ethSign(w.Owner, hash); err != nil {
		return nil, err
	}

	res, err := w.Bundler.Submit(ctx, op)
	var verr *aa.ValidationError
	if errors.As(err, &verr) {
		return &Outcome{Blocked: "the wallet refused to sign: " + verr.Error(), Reason: verr.Error()}, nil
	}
	if err != nil {
		return nil, err
	}
	if !res.Success {
		return &Outcome{TxHash: res.TxHash, Blocked: w.Explain(res.Revert), Reason: res.Revert.String()}, nil
	}
	return &Outcome{Executed: true, TxHash: res.TxHash}, nil
}

var sessionSignatureArgs = func() abi.Arguments {
	b, _ := abi.NewType("bytes", "", nil)
	return abi.Arguments{{Type: b}, {Type: b}}
}()

// ethSign is a raw ECDSA signature over a 32-byte hash with v in {27, 28}, as OpenZeppelin's ECDSA.recover expects.
func ethSign(k *ecdsa.PrivateKey, hash common.Hash) ([]byte, error) {
	sig, err := crypto.Sign(hash.Bytes(), k)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

// Explain turns a revert from the account into a sentence for the agent.
func (w *World) Explain(r chain.Revert) string {
	arg := func(i int) any { return r.Args[i] }
	addr := func(i int) common.Address { return arg(i).(common.Address) }
	num := func(i int) *big.Int { return arg(i).(*big.Int) }
	switch r.Name {
	case "SpendCapExceeded":
		t := w.tokenAt(addr(0))
		return fmt.Sprintf("blocked by wallet policy: the daily %s spending cap allows %s %s more today, this needed %s %s",
			t.Symbol, Format(t, num(2)), t.Symbol, Format(t, num(1)), t.Symbol)
	case "CounterpartyLimitExceeded":
		t := w.tokenAt(addr(0))
		return fmt.Sprintf("blocked by wallet policy: %s may receive at most %s %s more today, this needed %s %s",
			w.describe(addr(1)), Format(t, num(3)), t.Symbol, Format(t, num(2)), t.Symbol)
	case "CallNotAllowed":
		return fmt.Sprintf("blocked by wallet policy: calling function 0x%x on %s is not allowed",
			arg(1).([4]byte), w.describe(addr(0)))
	case "RecipientNotSelf":
		return fmt.Sprintf("blocked by wallet policy: calls to %s must send their output to this wallet",
			w.describe(addr(0)))
	case "ForbiddenTokenCall":
		return fmt.Sprintf("blocked by wallet policy: only transfer and approve may be called on %s",
			w.describe(addr(0)))
	case "ForbiddenTarget":
		return fmt.Sprintf("blocked by wallet policy: %s cannot be called", w.describe(addr(0)))
	case "MalformedCall":
		return "blocked by wallet policy: malformed call"
	case "SessionInactive":
		return "blocked by wallet policy: the agent's session key is not active"
	case "CallFailed":
		inner := chain.DecodeRevert(arg(1).([]byte), w.Bundler.Errors...)
		return fmt.Sprintf("call %d reverted: %s", num(0), inner)
	}
	return "reverted: " + r.String()
}

func (w *World) tokenAt(addr common.Address) Token {
	switch addr {
	case ETH.Address:
		return ETH
	case w.USDC.Address:
		return w.USDC
	}
	return Token{Symbol: addr.Hex(), Address: addr, Decimals: 18}
}

func (w *World) describe(addr common.Address) string {
	if name, ok := w.ContactName(addr); ok {
		return fmt.Sprintf("%s (%s)", name, addr.Hex())
	}
	return addr.Hex() + " (not in the address book)"
}

// PolicySummary describes the agent's limits in plain words, for its system prompt.
func (w *World) PolicySummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "- Daily caps: %s ETH and %s USDC in total.\n", Policy.ETHCap, Policy.USDCCap)
	fmt.Fprintf(&b, "- Per recipient per day: %s up to %s USDC, %s up to %s USDC. Other recipients: nothing.\n",
		w.Contacts[0].Name, Policy.AliceUSDC, w.Contacts[1].Name, Policy.BobUSDC)
	fmt.Fprintf(&b, "- The only contract you may call is the swap router (%s), and swaps must pay out to this wallet.\n",
		w.Swap.Hex())
	b.WriteString("- Anything over a limit needs the owner's passkey approval (request_approval).\n")
	return b.String()
}
