// Package chain holds the plain-transaction plumbing: loading Foundry artifacts, signing and sending transactions,
// deploying contracts and installing EIP-7702 delegations.
package chain

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"
)

// Key derives a deterministic private key from a label, so runs are reproducible and no key material is checked in.
func Key(label string) *ecdsa.PrivateKey {
	k, err := crypto.ToECDSA(crypto.Keccak256([]byte("leash/" + label)))
	if err != nil {
		panic(err) // a keccak output is a valid secp256k1 scalar with overwhelming probability
	}
	return k
}

// Addr is the address of a private key.
func Addr(k *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(k.PublicKey)
}

// Signer sends transactions from one EOA.
type Signer struct {
	Client  *ethclient.Client
	Key     *ecdsa.PrivateKey
	Address common.Address
	ChainID *big.Int
}

// NewSigner wraps a key for sending transactions.
func NewSigner(ctx context.Context, c *ethclient.Client, key *ecdsa.PrivateKey) (*Signer, error) {
	id, err := c.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	return &Signer{Client: c, Key: key, Address: Addr(key), ChainID: id}, nil
}

// ErrReverted is returned when a mined transaction has status 0.
var ErrReverted = errors.New("transaction reverted")

// Send signs and sends a transaction and waits for its receipt. Gas is estimated unless gas > 0.
func (s *Signer) Send(ctx context.Context, to *common.Address, value *big.Int, data []byte, gas uint64) (*types.Receipt, error) {
	if value == nil {
		value = new(big.Int)
	}
	nonce, err := s.Client.PendingNonceAt(ctx, s.Address)
	if err != nil {
		return nil, err
	}
	tip, feeCap, err := s.fees(ctx)
	if err != nil {
		return nil, err
	}
	if gas == 0 {
		gas, err = s.Client.EstimateGas(ctx, ethereum.CallMsg{From: s.Address, To: to, Value: value, Data: data})
		if err != nil {
			return nil, fmt.Errorf("estimate gas: %w", err)
		}
		gas = gas * 5 / 4
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: s.ChainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: feeCap, Gas: gas, To: to, Value: value, Data: data,
	})
	return s.sendSigned(ctx, tx)
}

// Deploy creates a contract from an artifact and constructor arguments.
func (s *Signer) Deploy(ctx context.Context, a *Artifact, args ...any) (common.Address, error) {
	ctorArgs, err := a.ABI.Pack("", args...)
	if err != nil {
		return common.Address{}, fmt.Errorf("pack %s constructor: %w", a.Name, err)
	}
	r, err := s.Send(ctx, nil, nil, append(append([]byte{}, a.Bytecode...), ctorArgs...), 0)
	if err != nil {
		return common.Address{}, fmt.Errorf("deploy %s: %w", a.Name, err)
	}
	return r.ContractAddress, nil
}

// Transact calls a contract method in a transaction.
func (s *Signer) Transact(ctx context.Context, to common.Address, a abi.ABI, method string, args ...any) (*types.Receipt, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", method, err)
	}
	return s.Send(ctx, &to, nil, data, 0)
}

// Delegate installs an EIP-7702 delegation from `authority` to `impl`, sponsored by this signer: the authority only
// signs the authorization, and this signer pays for the transaction that carries it.
func (s *Signer) Delegate(ctx context.Context, authority *ecdsa.PrivateKey, impl common.Address) error {
	authorityNonce, err := s.Client.PendingNonceAt(ctx, Addr(authority))
	if err != nil {
		return err
	}
	auth, err := types.SignSetCode(authority, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(s.ChainID),
		Address: impl,
		Nonce:   authorityNonce,
	})
	if err != nil {
		return fmt.Errorf("sign authorization: %w", err)
	}
	nonce, err := s.Client.PendingNonceAt(ctx, s.Address)
	if err != nil {
		return err
	}
	tip, feeCap, err := s.fees(ctx)
	if err != nil {
		return err
	}
	to := Addr(authority)
	tx := types.NewTx(&types.SetCodeTx{
		ChainID:   uint256.MustFromBig(s.ChainID),
		Nonce:     nonce,
		GasTipCap: uint256.MustFromBig(tip),
		GasFeeCap: uint256.MustFromBig(feeCap),
		Gas:       100_000,
		To:        to,
		Value:     new(uint256.Int),
		AuthList:  []types.SetCodeAuthorization{auth},
	})
	if _, err := s.sendSigned(ctx, tx); err != nil {
		return fmt.Errorf("delegate: %w", err)
	}
	code, err := s.Client.CodeAt(ctx, to, nil)
	if err != nil {
		return err
	}
	if want := append([]byte{0xef, 0x01, 0x00}, impl.Bytes()...); string(code) != string(want) {
		return fmt.Errorf("delegation not installed: code is %x", code)
	}
	return nil
}

// Call runs a read-only contract call and unpacks the result.
func Call(ctx context.Context, c *ethclient.Client, to common.Address, a abi.ABI, method string, args ...any) ([]any, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", method, err)
	}
	out, err := c.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", method, err)
	}
	return a.Unpack(method, out)
}

func (s *Signer) sendSigned(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(s.ChainID), s.Key)
	if err != nil {
		return nil, err
	}
	if err := s.Client.SendTransaction(ctx, signed); err != nil {
		return nil, err
	}
	r, err := WaitMined(ctx, s.Client, signed.Hash())
	if err != nil {
		return nil, err
	}
	if r.Status != types.ReceiptStatusSuccessful {
		return r, fmt.Errorf("%w: %s", ErrReverted, signed.Hash())
	}
	return r, nil
}

func (s *Signer) fees(ctx context.Context) (tip, feeCap *big.Int, err error) {
	head, err := s.Client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	tip = big.NewInt(1e9)
	feeCap = new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	return tip, feeCap, nil
}

// WaitMined polls for a receipt. Anvil mines on submission, so this normally returns on the first poll.
func WaitMined(ctx context.Context, c *ethclient.Client, hash common.Hash) (*types.Receipt, error) {
	for {
		r, err := c.TransactionReceipt(ctx, hash)
		if err == nil {
			return r, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
