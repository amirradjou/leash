package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Artifact is a compiled contract from Foundry's out/ directory.
type Artifact struct {
	Name     string
	ABI      abi.ABI
	Bytecode []byte
}

type forgeArtifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

// Artifacts loads compiled contracts from a Foundry out/ directory.
type Artifacts struct {
	Dir string
}

// FindArtifacts walks up from the working directory to the repository's contracts/out.
func FindArtifacts() (*Artifacts, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	for {
		out := filepath.Join(dir, "contracts", "out")
		if st, err := os.Stat(out); err == nil && st.IsDir() {
			return &Artifacts{Dir: out}, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, errors.New("contracts/out not found; run `make build` (forge build) first")
		}
		dir = parent
	}
}

// Load reads out/<file>/<name>.json, e.g. Load("LeashAccount.sol", "LeashAccount").
func (a *Artifacts) Load(file, name string) (*Artifact, error) {
	raw, err := os.ReadFile(filepath.Join(a.Dir, file, name+".json"))
	if err != nil {
		return nil, fmt.Errorf("load artifact %s: %w", name, err)
	}
	var fa forgeArtifact
	if err := json.Unmarshal(raw, &fa); err != nil {
		return nil, fmt.Errorf("parse artifact %s: %w", name, err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(fa.ABI)))
	if err != nil {
		return nil, fmt.Errorf("parse abi %s: %w", name, err)
	}
	code, err := hexutil.Decode(fa.Bytecode.Object)
	if err != nil {
		return nil, fmt.Errorf("decode bytecode %s: %w", name, err)
	}
	return &Artifact{Name: name, ABI: parsed, Bytecode: code}, nil
}
