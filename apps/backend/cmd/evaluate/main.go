// Command evaluate measures the risk engine on a synthetic dataset. It reports the recall and the false positive rate
// of the rules alone and of the rules with the model, and the latency of the model step. It writes the dataset as a
// CSV file and the results as a Markdown report.
//
// The dataset is synthetic. The numbers show how the parts behave, not how they would do on real traffic. Without the
// -ollama flag, the command measures the rules alone.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintln(os.Stderr, "evaluate:", err)
		os.Exit(1)
	}
}

// counts are the confusion counts of one way of deciding.
type counts struct {
	truePositive  int
	falsePositive int
	trueNegative  int
	falseNegative int
}

// count adds one login to the counts. The flagged argument tells whether the decider flagged the login, and suspicious
// tells whether it was suspicious in truth.
func (c *counts) count(flagged, suspicious bool) {
	switch {
	case flagged && suspicious:
		c.truePositive++
	case flagged:
		c.falsePositive++
	case suspicious:
		c.falseNegative++
	default:
		c.trueNegative++
	}
}

// recallShare formats the recall with its interval.
func (c counts) recallShare() string {
	return share(c.truePositive, c.truePositive+c.falseNegative)
}

// falsePositiveShare formats the false positive rate with its interval.
func (c counts) falsePositiveShare() string {
	return share(c.falsePositive, c.falsePositive+c.trueNegative)
}

// add adds the counts of other to c.
func (c *counts) add(other counts) {
	c.truePositive += other.truePositive
	c.falsePositive += other.falsePositive
	c.trueNegative += other.trueNegative
	c.falseNegative += other.falseNegative
}

// tally is what the evaluation found for the logins of one scenario.
type tally struct {
	rules    counts
	combined counts

	// raised is how many logins the model put at a higher level than the rules, and raisedRight is how many of them
	// were suspicious.
	raised      int
	raisedRight int
}

func run(args []string) error {
	set := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	ollamaURL := set.String("ollama", "", "the address of Ollama; empty measures the rules alone")
	model := set.String("model", "llama3.2:3b", "the model name and tag")
	digest := set.String("digest", "", "the digest the model must have; empty skips the check")
	n := set.Int("n", 300, "how many logins the baseline section has")
	per := set.Int("per", 50, "how many logins each hard scenario has; at least 40 for an interval that says something")
	seed := set.Uint64("seed", 2026, "the seed of the dataset")
	timeout := set.Duration("timeout", 30*time.Second, "how long one advice may take")
	out := set.String("out", "out/evaluation.md", "the report; the dataset goes next to it as dataset.csv")
	set.SetOutput(io.Discard)

	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			set.SetOutput(flag.CommandLine.Output())
			set.PrintDefaults()
		}

		return err
	}

	events := dataset(*seed, *n, *per)

	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		return err
	}

	csvFile, err := os.Create(filepath.Join(filepath.Dir(*out), "dataset.csv"))
	if err != nil {
		return err
	}

	if err := writeCSV(csvFile, events); err != nil {
		return errors.Join(err, csvFile.Close())
	}

	if err := csvFile.Close(); err != nil {
		return err
	}

	ctx := context.Background()
	var advisor *ai.Client
	if *ollamaURL != "" {
		advisor = ai.New(ai.Options{
			URL:         *ollamaURL,
			Model:       *model,
			Digest:      *digest,
			Timeout:     *timeout,
			Concurrency: 1,
		})
		if *digest != "" {
			if err := advisor.Check(ctx); err != nil {
				return err
			}
		}
	}

	tallies := make(map[string]*tally, len(scenarios))
	for _, scenario := range scenarios {
		tallies[scenario.Name] = &tally{}
	}

	var latencies []time.Duration
	refused := 0
	failed := 0
	failures := make(map[string]int)
	for _, event := range events {
		score := event.Signals.Score()
		level := ai.LevelOf(score)
		flaggedByRules := level != ai.LevelLow
		current := tallies[event.Scenario]
		current.rules.count(flaggedByRules, event.Suspicious)

		flagged := flaggedByRules
		if advisor != nil {
			pseudonym := sha256.Sum256([]byte(strconv.Itoa(event.ID)))
			started := time.Now()
			consultation, err := advisor.ReadOne(ctx, ai.Consultation{
				Summary: ai.Summary{
					Pseudonym:  hex.EncodeToString(pseudonym[:8]),
					Country:    event.Country,
					HourBucket: event.HourBucket,
					Factor:     event.Factor,
					Signals:    event.Signals,
					Score:      score,
					Level:      level.String(),
				},
			}, 0)
			advice := consultation.Advice
			latencies = append(latencies, time.Since(started))

			switch {
			case ai.IsRefusedAdvice(err):
				refused++
			case err != nil:
				failed++
				failures[err.Error()]++
			case advice.Level > level:
				current.raised++
				flagged = true

				if event.Suspicious {
					current.raisedRight++
				}
			}
		}

		current.combined.count(flagged, event.Suspicious)
		fmt.Fprintf(os.Stderr, "\r%d/%d", event.ID, len(events))
	}

	fmt.Fprintln(os.Stderr)

	for cause, times := range failures {
		fmt.Fprintf(os.Stderr, "evaluate: %d requests failed: %s\n", times, cause)
	}

	report, err := os.Create(*out)
	if err != nil {
		return err
	}

	writeReport(report, reportInput{
		tallies:   tallies,
		events:    len(events),
		seed:      *seed,
		advised:   advisor != nil,
		model:     *model,
		digest:    *digest,
		url:       *ollamaURL,
		latencies: latencies,
		refused:   refused,
		failed:    failed,
	})

	return report.Close()
}

// reportInput is what [writeReport] needs to write the report.
type reportInput struct {
	tallies   map[string]*tally
	events    int
	seed      uint64
	advised   bool
	model     string
	digest    string
	url       string
	latencies []time.Duration
	refused   int
	failed    int
}

// section adds up the tallies of the baseline scenarios if baseline is set, and of the hard scenarios otherwise.
func section(tallies map[string]*tally, baseline bool) tally {
	var sum tally
	for _, scenario := range scenarios {
		if scenario.Baseline != baseline {
			continue
		}

		current := tallies[scenario.Name]
		sum.rules.add(current.rules)
		sum.combined.add(current.combined)
		sum.raised += current.raised
		sum.raisedRight += current.raisedRight
	}

	return sum
}

// writeReport writes the Markdown report of the evaluation to w.
func writeReport(w io.Writer, in reportInput) {
	fmt.Fprintf(w, "# Evaluation of the risk engine\n\n")
	fmt.Fprintf(w, "Dataset: %d synthetic logins from seed %d, written to dataset.csv next to this report, with the scenario of every login. ", in.events, in.seed)
	fmt.Fprintf(w, "The labels are true by construction; the numbers say nothing about real traffic. ")
	fmt.Fprintf(w, "Every share has its 95 percent Wilson interval in brackets.\n\n")

	for _, part := range []struct {
		title    string
		baseline bool
	}{
		{
			"Baseline mix",
			true,
		},
		{
			"Hard scenarios",
			false,
		},
	} {
		sum := section(in.tallies, part.baseline)
		fmt.Fprintf(w, "## %s\n\n| Decider | Recall | False positive rate |\n| --- | --- | --- |\n", part.title)
		fmt.Fprintf(w, "| rules alone | %s | %s |\n", sum.rules.recallShare(), sum.rules.falsePositiveShare())

		if in.advised {
			fmt.Fprintf(w, "| rules with the model | %s | %s |\n", sum.combined.recallShare(), sum.combined.falsePositiveShare())
		}

		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## Per scenario\n\nThe metric is the recall for a suspicious scenario and the false positive rate for a legitimate one.\n\n")
	fmt.Fprintf(w, "| Scenario | Label | Metric | Logins | Rules alone | Rules with the model | Raised by the model |\n| --- | --- | --- | --- | --- | --- | --- |\n")

	for _, scenario := range scenarios {
		current := in.tallies[scenario.Name]
		label, metric := "legitimate", "false positive rate"
		rulesShare, combinedShare := current.rules.falsePositiveShare(), current.combined.falsePositiveShare()
		total := current.rules.falsePositive + current.rules.trueNegative

		if scenario.Suspicious {
			label, metric = "suspicious", "recall"
			rulesShare, combinedShare = current.rules.recallShare(), current.combined.recallShare()
			total = current.rules.truePositive + current.rules.falseNegative
		}

		combinedCell, raisedCell := "not asked", "not asked"
		if in.advised {
			combinedCell = combinedShare
			raisedCell = fmt.Sprintf("%d of %d", current.raised, total)
		}

		fmt.Fprintf(w, "| %s | %s | %s | %d | %s | %s | %s |\n", scenario.Name, label, metric, total, rulesShare, combinedCell, raisedCell)
	}

	fmt.Fprintln(w)

	if !in.advised {
		fmt.Fprintf(w, "No model was asked: pass -ollama to measure the combined decider.\n")
		return
	}

	raised, raisedRight := 0, 0
	for _, current := range in.tallies {
		raised += current.raised
		raisedRight += current.raisedRight
	}

	slices.Sort(in.latencies)
	p50 := in.latencies[len(in.latencies)/2]
	p95 := in.latencies[len(in.latencies)*95/100]
	fmt.Fprintf(w, "Model: %s (digest %s) through Ollama at %s, one request at a time. ", in.model, in.digest, in.url)
	fmt.Fprintf(w, "Hardware: %s/%s, %d CPUs, the machine that ran this command.\n\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Fprintf(w, "| Latency of the model step | |\n| --- | --- |\n| p50 | %s |\n| p95 | %s |\n\n", p50.Round(time.Millisecond), p95.Round(time.Millisecond))
	fmt.Fprintf(w, "The model raised %d of %d logins, and %d of those were suspicious. %d responses were refused by the strict check and %d requests failed; both count as no advice.\n", raised, in.events, raisedRight, in.refused, in.failed)
}
