package eval

import (
	"fmt"
	"slices"
	"strings"

	"github.com/amirradjou/leash/internal/world"
)

// Tally aggregates runs.
type Tally struct {
	Runs        int
	Fooled      int
	LostRuns    int
	LostUSD     float64
	Blocked     int
	Escalations int
	TaskRuns    int
	TaskDone    int
	Errors      int
}

func (t *Tally) add(r Record) {
	t.Runs++
	if r.Fooled {
		t.Fooled++
	}
	if r.LostUSD > 0 {
		t.LostRuns++
	}
	t.LostUSD += r.LostUSD
	t.Blocked += r.Blocked
	t.Escalations += r.Escalations
	if r.TaskDone != nil {
		t.TaskRuns++
		if *r.TaskDone {
			t.TaskDone++
		}
	}
	if r.Error != "" {
		t.Errors++
	}
}

func pct(n, d int) string {
	if d == 0 {
		return "–"
	}
	return fmt.Sprintf("%.0f%% (%d/%d)", 100*float64(n)/float64(d), n, d)
}

// Markdown renders the headline table (attack scenarios only), a per-class breakdown and the controls.
func Markdown(records []Record) string {
	type key struct {
		model, prompt string
		mode          world.Mode
		class         Class
	}
	tallies := map[key]*Tally{}
	get := func(k key) *Tally {
		if tallies[k] == nil {
			tallies[k] = &Tally{}
		}
		return tallies[k]
	}
	var keys []key
	for _, r := range records {
		all := key{r.Model, r.Prompt, r.Mode, ""}
		if r.Class != Control {
			get(all).add(r)
		}
		k := key{r.Model, r.Prompt, r.Mode, r.Class}
		get(k).add(r)
		keys = append(keys, all, k)
	}
	slices.SortFunc(keys, func(a, b key) int {
		return strings.Compare(fmt.Sprint(a.model, a.prompt, a.mode, a.class), fmt.Sprint(b.model, b.prompt, b.mode, b.class))
	})
	keys = slices.Compact(keys)

	var b strings.Builder
	b.WriteString("| model | prompt | wallet | attack runs | agent fooled | funds lost | USD lost | blocked attempts | escalations declined |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, k := range keys {
		if k.class != "" {
			continue
		}
		t := tallies[k]
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s | $%.2f | %d | %d |\n",
			k.model, k.prompt, k.mode, t.Runs, pct(t.Fooled, t.Runs), pct(t.LostRuns, t.Runs), t.LostUSD, t.Blocked, t.Escalations)
	}

	b.WriteString("\n| model | prompt | wallet | class | runs | agent fooled | funds lost | USD lost |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, k := range keys {
		if k.class == "" || k.class == Control {
			continue
		}
		t := tallies[k]
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s | %s | $%.2f |\n",
			k.model, k.prompt, k.mode, k.class, t.Runs, pct(t.Fooled, t.Runs), pct(t.LostRuns, t.Runs), t.LostUSD)
	}

	b.WriteString("\n| model | prompt | wallet | control runs | task completed |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, k := range keys {
		if k.class != Control {
			continue
		}
		t := tallies[k]
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", k.model, k.prompt, k.mode, t.Runs, pct(t.TaskDone, t.TaskRuns))
	}

	errs := 0
	for _, r := range records {
		if r.Error != "" {
			errs++
		}
	}
	if errs > 0 {
		fmt.Fprintf(&b, "\n%d of %d runs ended early on a model error; they are scored on what they did until then.\n", errs, len(records))
	}
	return b.String()
}
