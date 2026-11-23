// Package anvil runs a throwaway local chain for the agent and the eval harness. Nothing in leash talks to a live
// network: every account, contract and attack lives on an Anvil instance started here.
package anvil

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// ChainID is the chain id every Anvil instance is started with.
const ChainID = 31337

// Node is a running Anvil process.
type Node struct {
	URL    string
	RPC    *rpc.Client
	Client *ethclient.Client
	cmd    *exec.Cmd
}

// FindBinary looks for anvil on PATH, then in Foundry's default install directory.
func FindBinary() (string, error) {
	if p, err := exec.LookPath("anvil"); err == nil {
		return p, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".foundry", "bin", "anvil")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("anvil not found on PATH or in ~/.foundry/bin; install Foundry from https://getfoundry.sh")
}

// DefaultHardfork is the EVM version every chain runs unless a caller asks for another. Prague is the first with
// EIP-7702; osaka adds the P-256 precompile (EIP-7951) that the passkey path uses when it is there.
const DefaultHardfork = "prague"

// Start launches Anvil on a free port with the default hardfork and waits until it answers RPC calls.
func Start(ctx context.Context) (*Node, error) {
	return StartHardfork(ctx, DefaultHardfork)
}

// StartHardfork is Start on a given hardfork, which must be prague or later for EIP-7702.
func StartHardfork(ctx context.Context, hardfork string) (*Node, error) {
	bin, err := FindBinary()
	if err != nil {
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin,
		"--port", fmt.Sprint(port),
		"--chain-id", fmt.Sprint(ChainID),
		"--hardfork", hardfork,
		"--accounts", "1",
		"--silent",
	)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start anvil: %w", err)
	}
	n := &Node{URL: fmt.Sprintf("http://127.0.0.1:%d", port), cmd: cmd}

	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := n.connect(ctx); err == nil {
			return n, nil
		} else if time.Now().After(deadline) {
			n.Close()
			return nil, fmt.Errorf("anvil did not come up: %w", err)
		}
		select {
		case <-ctx.Done():
			n.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (n *Node) connect(ctx context.Context) error {
	c, err := rpc.DialContext(ctx, n.URL)
	if err != nil {
		return err
	}
	var id hexutil.Big
	if err := c.CallContext(ctx, &id, "eth_chainId"); err != nil {
		c.Close()
		return err
	}
	n.RPC = c
	n.Client = ethclient.NewClient(c)
	return nil
}

// Close stops the Anvil process.
func (n *Node) Close() {
	if n.RPC != nil {
		n.RPC.Close()
	}
	if n.cmd != nil && n.cmd.Process != nil {
		_ = n.cmd.Process.Kill()
		_ = n.cmd.Wait()
	}
}

// Snapshot records the chain state. A snapshot id can be reverted to once.
func (n *Node) Snapshot(ctx context.Context) (string, error) {
	var id string
	err := n.RPC.CallContext(ctx, &id, "evm_snapshot")
	return id, err
}

// Revert restores a snapshot taken with Snapshot.
func (n *Node) Revert(ctx context.Context, id string) error {
	var ok bool
	if err := n.RPC.CallContext(ctx, &ok, "evm_revert", id); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("evm_revert %s: snapshot not found", id)
	}
	return nil
}

// SetBalance overwrites an account's ETH balance.
func (n *Node) SetBalance(ctx context.Context, addr common.Address, wei *big.Int) error {
	return n.RPC.CallContext(ctx, nil, "anvil_setBalance", addr, hexutil.EncodeBig(wei))
}

// IncreaseTime moves the chain clock forward and mines a block so the new time is visible.
func (n *Node) IncreaseTime(ctx context.Context, d time.Duration) error {
	if err := n.RPC.CallContext(ctx, nil, "evm_increaseTime", int64(d/time.Second)); err != nil {
		return err
	}
	return n.RPC.CallContext(ctx, nil, "evm_mine")
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
