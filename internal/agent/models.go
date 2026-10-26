package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// DefaultModel is the Claude model used when none is given.
const DefaultModel = "claude-opus-5-5"

// OllamaURL is where a local Ollama serves its Anthropic-compatible Messages endpoint.
const OllamaURL = "http://localhost:11434"

// Messages calls a Messages API with the official SDK: Anthropic's, or any compatible endpoint such as Ollama's.
type Messages struct {
	client anthropic.Client
	model  string
	// effort is sent as output_config.effort for Claude models; local models get a plain request.
	effort string
}

// NewModel resolves a model name: "ollama:<tag>" talks to a local Ollama, anything else to the Anthropic API with the
// SDK's usual credentials (ANTHROPIC_API_KEY, or an `ant auth login` profile).
func NewModel(name, effort string) Model {
	if tag, ok := strings.CutPrefix(name, "ollama:"); ok {
		return &Messages{
			client: anthropic.NewClient(option.WithBaseURL(OllamaURL), option.WithAPIKey("ollama")),
			model:  tag,
		}
	}
	return &Messages{client: anthropic.NewClient(), model: name, effort: effort}
}

func (m *Messages) Name() string { return m.model }

func (m *Messages) Next(ctx context.Context, p anthropic.MessageNewParams) (*anthropic.Message, error) {
	p.Model = anthropic.Model(m.model)
	if m.effort != "" {
		p.OutputConfig = anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffort(m.effort)}
	}
	return m.client.Messages.New(ctx, p)
}

// ScriptStep is one tool call a Scripted model makes.
type ScriptStep struct {
	Tool  string
	Input any
	// IfBlocked runs the step only when the previous tool result was an error, e.g. escalating a blocked payment.
	IfBlocked bool
}

// Scripted is a deterministic stand-in for a model. Given the attacker's plan it is a perfectly fooled agent, which
// is the worst case the on-chain policy has to hold against.
type Scripted struct {
	Label string
	Steps []ScriptStep
	next  int
}

func (s *Scripted) Name() string { return "scripted:" + s.Label }

func (s *Scripted) Next(_ context.Context, p anthropic.MessageNewParams) (*anthropic.Message, error) {
	lastFailed := lastToolResultFailed(p.Messages)
	for s.next < len(s.Steps) {
		step := s.Steps[s.next]
		s.next++
		if step.IfBlocked && !lastFailed {
			continue
		}
		return scriptedMessage(fmt.Sprintf("toolu_%02d", s.next), map[string]any{
			"type": "tool_use", "id": fmt.Sprintf("toolu_%02d", s.next), "name": step.Tool, "input": step.Input,
		}, "tool_use")
	}
	return scriptedMessage("done", map[string]any{"type": "text", "text": "Done."}, "end_turn")
}

func lastToolResultFailed(msgs []anthropic.MessageParam) bool {
	if len(msgs) == 0 {
		return false
	}
	for _, block := range msgs[len(msgs)-1].Content {
		if r := block.OfToolResult; r != nil && r.IsError.Value {
			return true
		}
	}
	return false
}

// scriptedMessage builds an assistant message the same way the SDK would decode one from the API.
func scriptedMessage(id string, block map[string]any, stop string) (*anthropic.Message, error) {
	raw, err := json.Marshal(map[string]any{
		"id": "msg_" + id, "type": "message", "role": "assistant", "model": "scripted",
		"content": []any{block}, "stop_reason": stop, "stop_sequence": nil,
		"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
	})
	if err != nil {
		return nil, err
	}
	var m anthropic.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
