// Package agent is the LLM side of leash: a tool-use loop over the Anthropic Messages API, the wallet tools the
// model can call, and the model backends (Claude, a local model through the same SDK, and a scripted stand-in).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// Model produces the next assistant message for a conversation.
type Model interface {
	Name() string
	Next(ctx context.Context, p anthropic.MessageNewParams) (*anthropic.Message, error)
}

// Tool is a client-side tool the model can call.
type Tool struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
	// Acts marks tools that move funds or ask to. The eval looks at these to decide whether the agent was fooled.
	Acts bool
	Run  func(ctx context.Context, input json.RawMessage) (out string, isError bool, err error)
}

func (t Tool) param() anthropic.ToolUnionParam {
	return anthropic.ToolUnionParam{OfTool: &anthropic.ToolParam{
		Name:        t.Name,
		Description: anthropic.String(t.Description),
		InputSchema: anthropic.ToolInputSchemaParam{Properties: t.Properties, Required: t.Required},
	}}
}

// Step is one tool call and its result.
type Step struct {
	Turn    int             `json:"turn"`
	Tool    string          `json:"tool"`
	Acts    bool            `json:"acts"`
	Input   json.RawMessage `json:"input"`
	Output  string          `json:"output"`
	IsError bool            `json:"is_error,omitempty"`
}

// Transcript is everything the agent did in one run.
type Transcript struct {
	Steps        []Step   `json:"steps"`
	Text         []string `json:"text"`
	Turns        int      `json:"turns"`
	StopReason   string   `json:"stop_reason"`
	InputTokens  int64    `json:"input_tokens"`
	OutputTokens int64    `json:"output_tokens"`
	Duration     float64  `json:"duration_s"`
}

// Config for one run.
type Config struct {
	System   string
	Tools    []Tool
	MaxTurns int
	// MaxTokens per response. Non-streaming requests stay well under SDK timeouts at this size.
	MaxTokens int64
}

// Run gives the agent a task and loops until it stops calling tools or runs out of turns. The conversation is only
// ever appended to.
func Run(ctx context.Context, m Model, cfg Config, task string) (*Transcript, error) {
	if cfg.MaxTurns == 0 {
		cfg.MaxTurns = 10
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 16000
	}
	byName := make(map[string]Tool, len(cfg.Tools))
	params := make([]anthropic.ToolUnionParam, len(cfg.Tools))
	for i, t := range cfg.Tools {
		byName[t.Name] = t
		params[i] = t.param()
	}

	start := time.Now()
	tr := &Transcript{}
	defer func() { tr.Duration = time.Since(start).Seconds() }()
	messages := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(task))}

	for tr.Turns < cfg.MaxTurns {
		tr.Turns++
		resp, err := m.Next(ctx, anthropic.MessageNewParams{
			MaxTokens: cfg.MaxTokens,
			System:    []anthropic.TextBlockParam{{Text: cfg.System}},
			Messages:  messages,
			Tools:     params,
		})
		if err != nil {
			return tr, fmt.Errorf("turn %d: %w", tr.Turns, err)
		}
		tr.InputTokens += resp.Usage.InputTokens
		tr.OutputTokens += resp.Usage.OutputTokens
		tr.StopReason = string(resp.StopReason)
		messages = append(messages, resp.ToParam())

		var results []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			switch b := block.AsAny().(type) {
			case anthropic.TextBlock:
				if b.Text != "" {
					tr.Text = append(tr.Text, b.Text)
				}
			case anthropic.ToolUseBlock:
				step := Step{Turn: tr.Turns, Tool: b.Name, Input: json.RawMessage(b.JSON.Input.Raw())}
				tool, ok := byName[b.Name]
				switch {
				case !ok:
					step.Output, step.IsError = "unknown tool "+b.Name, true
				default:
					step.Acts = tool.Acts
					out, isErr, err := tool.Run(ctx, step.Input)
					if err != nil {
						return tr, fmt.Errorf("tool %s: %w", b.Name, err)
					}
					step.Output, step.IsError = out, isErr
				}
				tr.Steps = append(tr.Steps, step)
				results = append(results, anthropic.NewToolResultBlock(b.ID, step.Output, step.IsError))
			}
		}
		// Refusals, max_tokens and end_turn all end the run; the stop reason is recorded either way.
		if resp.StopReason != anthropic.StopReasonToolUse || len(results) == 0 {
			break
		}
		messages = append(messages, anthropic.NewUserMessage(results...))
	}
	return tr, nil
}
