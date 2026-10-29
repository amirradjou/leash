package chain

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// Revert is decoded revert data: a custom error from one of the known ABIs, Error(string), or Panic(uint256).
type Revert struct {
	Name string
	Args []any
	// Inputs are the error's parameters, so callers can name the arguments.
	Inputs abi.Arguments
	Raw    []byte
}

var (
	errorStringSelector = []byte{0x08, 0xc3, 0x79, 0xa0}
	panicSelector       = []byte{0x4e, 0x48, 0x7b, 0x71}
)

// DecodeRevert matches revert data against the custom errors of the given ABIs. Unknown data comes back with an
// empty Name and only Raw set.
func DecodeRevert(data []byte, abis ...abi.ABI) Revert {
	r := Revert{Raw: data}
	if len(data) < 4 {
		return r
	}
	if bytes.Equal(data[:4], errorStringSelector) {
		if msg, err := abi.UnpackRevert(data); err == nil {
			r.Name, r.Args = "Error", []any{msg}
		}
		return r
	}
	if bytes.Equal(data[:4], panicSelector) {
		if msg, err := abi.UnpackRevert(data); err == nil {
			r.Name, r.Args = "Panic", []any{msg}
		}
		return r
	}
	for _, a := range abis {
		for _, e := range a.Errors {
			if !bytes.Equal(e.ID[:4], data[:4]) {
				continue
			}
			args, err := e.Inputs.Unpack(data[4:])
			if err != nil {
				continue
			}
			r.Name, r.Args, r.Inputs = e.Name, args, e.Inputs
			return r
		}
	}
	return r
}

// String renders the revert like Solidity source: Name(arg, arg).
func (r Revert) String() string {
	if r.Name == "" {
		return fmt.Sprintf("unknown revert 0x%x", r.Raw)
	}
	parts := make([]string, len(r.Args))
	for i, a := range r.Args {
		if b, ok := a.([]byte); ok {
			parts[i] = hexutil.Encode(b)
			continue
		}
		parts[i] = fmt.Sprint(a)
	}
	return r.Name + "(" + strings.Join(parts, ", ") + ")"
}

// RevertData extracts the revert payload from an eth_call / eth_estimateGas error.
func RevertData(err error) ([]byte, bool) {
	var de rpc.DataError
	if !errors.As(err, &de) {
		return nil, false
	}
	s, ok := de.ErrorData().(string)
	if !ok {
		return nil, false
	}
	b, err := hexutil.Decode(s)
	return b, err == nil
}
