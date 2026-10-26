// Command leash runs an LLM agent whose wallet is a policy-constrained smart account.
//
//	leash eval [flags]   run the prompt-injection suite on a local Anvil chain
//	leash demo [flags]   give the agent one task, approving escalations yourself
//	leash version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/amirradjou/leash/internal/agent"
	"github.com/amirradjou/leash/internal/anvil"
	"github.com/amirradjou/leash/internal/chain"
	"github.com/amirradjou/leash/internal/eval"
	"github.com/amirradjou/leash/internal/world"
)

const version = "0.1.0"

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintf(stdout, "leash %s\n", version)
		return err
	case "eval":
		return runEval(ctx, args[1:], stdout, stderr)
	case "demo":
		return runDemo(ctx, args[1:], stdin, stdout)
	}
	return usageError()
}

func usageError() error {
	return errors.New("usage: leash eval|demo|version [flags]; run `leash eval -h` for flags")
}

func runEval(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	model := fs.String("model", "scripted", `"scripted" (a fully fooled agent), "ollama:<tag>", or a Claude model id such as `+agent.DefaultModel)
	effort := fs.String("effort", "medium", "output_config.effort for Claude models")
	modes := fs.String("modes", "leash,unguarded", "wallet modes to run")
	prompt := fs.String("prompt", agent.Plain, "system prompt variant: plain or guarded")
	trials := fs.Int("trials", 1, "runs per scenario and mode")
	only := fs.String("scenarios", "", "comma-separated scenario ids (default: all)")
	out := fs.String("out", "results", "directory for the JSONL records and summary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := eval.Options{ModelName: *model, Prompt: *prompt, Trials: *trials, Progress: stderr}
	if *model == "scripted" {
		opts.Scripted = true
	} else {
		opts.Model = func() agent.Model { return agent.NewModel(*model, *effort) }
	}
	for _, m := range strings.Split(*modes, ",") {
		opts.Modes = append(opts.Modes, world.Mode(strings.TrimSpace(m)))
	}
	for _, s := range eval.Scenarios {
		if *only == "" || slices.Contains(strings.Split(*only, ","), s.ID) {
			opts.Scenarios = append(opts.Scenarios, s)
		}
	}
	if len(opts.Scenarios) == 0 {
		return fmt.Errorf("no scenarios match %q", *only)
	}

	w, stop, err := startWorld(ctx)
	if err != nil {
		return err
	}
	defer stop()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	base := filepath.Join(*out, fmt.Sprintf("%s-%s-%s", stamp, safe(*model), *prompt))
	f, err := os.Create(base + ".jsonl")
	if err != nil {
		return err
	}
	defer f.Close()
	opts.Records = f

	records, runErr := eval.Run(ctx, w, opts)
	md := eval.Markdown(records)
	if err := os.WriteFile(base+".md", []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\n%s\nrecords: %s.jsonl\n", md, base)
	return runErr
}

func runDemo(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	model := fs.String("model", agent.DefaultModel, `"ollama:<tag>" or a Claude model id`)
	effort := fs.String("effort", "medium", "output_config.effort for Claude models")
	mode := fs.String("mode", string(world.Leashed), "leash or unguarded")
	prompt := fs.String("prompt", agent.Plain, "plain or guarded")
	task := fs.String("task", "What's in my wallet?", "what to ask the agent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w, stop, err := startWorld(ctx)
	if err != nil {
		return err
	}
	defer stop()

	env := &agent.Env{
		W: w, Wallet: &world.Wallet{W: w, Mode: world.Mode(*mode)},
		Approver: &terminalApprover{w: w, in: bufio.NewReader(stdin), out: stdout},
	}
	cfg := agent.Config{System: agent.SystemPrompt(w, *prompt), Tools: env.Tools()}
	tr, err := agent.Run(ctx, agent.NewModel(*model, *effort), cfg, *task)
	if tr != nil {
		for _, s := range tr.Steps {
			fmt.Fprintf(stdout, "-> %s %s\n<- %s\n\n", s.Tool, s.Input, s.Output)
		}
		fmt.Fprintln(stdout, strings.Join(tr.Text, "\n"))
	}
	return err
}

// terminalApprover asks the person at the keyboard, then signs with the software passkey.
type terminalApprover struct {
	w   *world.World
	in  *bufio.Reader
	out io.Writer
}

func (a *terminalApprover) Approve(_ context.Context, req agent.ApprovalRequest) (bool, string) {
	to := req.To.Hex()
	if name, ok := a.w.ContactName(req.To); ok {
		to = name + " (" + to + ")"
	}
	fmt.Fprintf(a.out, "\nThe agent asks to send %s %s to %s.\nReason: %s\nApprove with passkey? [y/N] ",
		world.Format(req.Token, req.Amount), req.Token.Symbol, to, req.Reason)
	line, _ := a.in.ReadString('\n')
	if strings.EqualFold(strings.TrimSpace(line), "y") {
		return true, ""
	}
	return false, "the owner said no"
}

func startWorld(ctx context.Context) (*world.World, func(), error) {
	arts, err := chain.FindArtifacts()
	if err != nil {
		return nil, nil, err
	}
	node, err := anvil.Start(ctx)
	if err != nil {
		return nil, nil, err
	}
	w, err := world.Build(ctx, node, arts)
	if err != nil {
		node.Close()
		return nil, nil, err
	}
	return w, node.Close, nil
}

func safe(s string) string {
	return strings.NewReplacer(":", "-", "/", "-").Replace(s)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
