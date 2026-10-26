// Command leash runs an LLM agent whose wallet is a policy-constrained smart account.
package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.0.0-dev"

func run(w io.Writer) error {
	_, err := fmt.Fprintf(w, "leash %s\n", version)
	return err
}

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
