// Package aa builds, signs and bundles ERC-4337 v0.8 user operations. On a local chain there is no public bundler, so
// leash submits operations to the EntryPoint itself with handleOps, from a funded bundler EOA.
package aa

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/amirradjou/leash/internal/chain"
)

// UserOp is a PackedUserOperation. Field names match the Solidity struct so go-ethereum's ABI packer can encode it.
type UserOp struct {
	Sender             common.Address
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   [32]byte
	PreVerificationGas *big.Int
	GasFees            [32]byte
	PaymasterAndData   []byte
	Signature          []byte
}

// Gas limits for every op. Generous on purpose: a passkey escalation verifies P-256 in Solidity during validation.
const (
	VerificationGas    = 2_000_000
	CallGas            = 3_000_000
	PreVerificationGas = 100_000
	handleOpsGas       = 10_000_000
)

// Pack128 packs two uint128 values into one word, high then low, as accountGasLimits and gasFees are.
func Pack128(hi, lo *big.Int) [32]byte {
	var w [32]byte
	hi.FillBytes(w[:16])
	lo.FillBytes(w[16:])
	return w
}

// Bundler submits user operations to an EntryPoint.
type Bundler struct {
	Signer     *chain.Signer // pays for handleOps and collects the fees
	EntryPoint common.Address
	ABI        abi.ABI
	// Errors decode revert data from accounts and the contracts they call.
	Errors []abi.ABI
}

// NewOp fills nonce, gas limits and fees for an operation from `sender`. The caller signs it.
func (b *Bundler) NewOp(ctx context.Context, sender common.Address, callData []byte) (*UserOp, error) {
	out, err := chain.Call(ctx, b.Signer.Client, b.EntryPoint, b.ABI, "getNonce", sender, big.NewInt(0))
	if err != nil {
		return nil, err
	}
	head, err := b.Signer.Client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	tip := big.NewInt(1e9)
	maxFee := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	return &UserOp{
		Sender:             sender,
		Nonce:              out[0].(*big.Int),
		CallData:           callData,
		AccountGasLimits:   Pack128(big.NewInt(VerificationGas), big.NewInt(CallGas)),
		PreVerificationGas: big.NewInt(PreVerificationGas),
		GasFees:            Pack128(tip, maxFee),
	}, nil
}

// Hash is the EntryPoint's userOpHash (EIP-712 in v0.8), which the account's signers sign.
func (b *Bundler) Hash(ctx context.Context, op *UserOp) (common.Hash, error) {
	out, err := chain.Call(ctx, b.Signer.Client, b.EntryPoint, b.ABI, "getUserOpHash", *op)
	if err != nil {
		return common.Hash{}, err
	}
	return common.Hash(out[0].([32]byte)), nil
}

// ValidationError means the EntryPoint refused the operation before executing it: a bad signature, an expired
// session, an empty gas tank. Nothing was sent on chain.
type ValidationError struct {
	Code  string // the EntryPoint's "AAxx ..." reason
	Inner chain.Revert
}

func (e *ValidationError) Error() string {
	if len(e.Inner.Raw) > 0 {
		return e.Code + ": " + e.Inner.String()
	}
	return e.Code
}

// Result of an operation that made it on chain.
type Result struct {
	TxHash  common.Hash
	Success bool
	// Revert is the account's revert when Success is false.
	Revert chain.Revert
	Logs   []*types.Log
	// GasUsed by the whole handleOps transaction, validation and execution included.
	GasUsed uint64
}

// Submit runs handleOps for one operation. It dry-runs first, so a validation failure returns *ValidationError
// without spending gas; an execution revert is a Result with Success false.
func (b *Bundler) Submit(ctx context.Context, op *UserOp) (*Result, error) {
	data, err := b.ABI.Pack("handleOps", []UserOp{*op}, b.Signer.Address)
	if err != nil {
		return nil, fmt.Errorf("pack handleOps: %w", err)
	}
	msg := ethereum.CallMsg{From: b.Signer.Address, To: &b.EntryPoint, Data: data, Gas: handleOpsGas}
	if _, err := b.Signer.Client.CallContract(ctx, msg, nil); err != nil {
		if raw, ok := chain.RevertData(err); ok {
			return nil, b.validationError(raw)
		}
		return nil, fmt.Errorf("simulate handleOps: %w", err)
	}

	receipt, err := b.Signer.Send(ctx, &b.EntryPoint, nil, data, handleOpsGas)
	if err != nil {
		return nil, fmt.Errorf("handleOps: %w", err)
	}
	res := &Result{TxHash: receipt.TxHash, Logs: receipt.Logs, GasUsed: receipt.GasUsed}
	opEvent, revertEvent := b.ABI.Events["UserOperationEvent"], b.ABI.Events["UserOperationRevertReason"]
	for _, l := range receipt.Logs {
		if l.Address != b.EntryPoint || len(l.Topics) == 0 {
			continue
		}
		switch l.Topics[0] {
		case opEvent.ID:
			v, err := opEvent.Inputs.NonIndexed().Unpack(l.Data)
			if err != nil {
				return nil, err
			}
			res.Success = v[1].(bool)
		case revertEvent.ID:
			v, err := revertEvent.Inputs.NonIndexed().Unpack(l.Data)
			if err != nil {
				return nil, err
			}
			res.Revert = chain.DecodeRevert(v[1].([]byte), b.Errors...)
		}
	}
	return res, nil
}

func (b *Bundler) validationError(raw []byte) error {
	r := chain.DecodeRevert(raw, b.ABI)
	switch r.Name {
	case "FailedOp":
		return &ValidationError{Code: r.Args[1].(string)}
	case "FailedOpWithRevert":
		return &ValidationError{Code: r.Args[1].(string), Inner: chain.DecodeRevert(r.Args[2].([]byte), b.Errors...)}
	}
	return errors.New("handleOps reverted: " + r.String())
}
