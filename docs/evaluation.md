# Evaluation of the risk engine

Dataset: 620 synthetic logins from seed 2026, written to dataset.csv next to this report, with the scenario of every login. The labels are true by construction; the numbers say nothing about real traffic. Every share has its 95 percent Wilson interval in brackets.

## Baseline mix

| Decider | Recall | False positive rate |
| --- | --- | --- |
| rules alone | 0.855 (0.747-0.922) | 0.000 (0.000-0.016) |
| rules with the model | 0.855 (0.747-0.922) | 0.000 (0.000-0.016) |

## Hard scenarios

| Decider | Recall | False positive rate |
| --- | --- | --- |
| rules alone | 0.725 (0.651-0.788) | 0.713 (0.638-0.777) |
| rules with the model | 0.725 (0.651-0.788) | 0.713 (0.638-0.777) |

## Per scenario

The metric is the recall for a suspicious scenario and the false positive rate for a legitimate one.

| Scenario | Label | Metric | Logins | Rules alone | Rules with the model | Raised by the model |
| --- | --- | --- | --- | --- | --- | --- |
| baseline-legitimate | legitimate | false positive rate | 238 | 0.000 (0.000-0.016) | 0.000 (0.000-0.016) | 0 of 238 |
| baseline-failure-burst | suspicious | recall | 11 | 1.000 (0.741-1.000) | 1.000 (0.741-1.000) | 0 of 11 |
| baseline-new-device-odd-hour | suspicious | recall | 19 | 1.000 (0.832-1.000) | 1.000 (0.832-1.000) | 0 of 19 |
| baseline-impossible-travel | suspicious | recall | 11 | 1.000 (0.741-1.000) | 1.000 (0.741-1.000) | 0 of 11 |
| baseline-wrong-codes | suspicious | recall | 12 | 1.000 (0.758-1.000) | 1.000 (0.758-1.000) | 0 of 12 |
| baseline-weak-new-credential | suspicious | recall | 9 | 0.000 (0.000-0.299) | 0.000 (0.000-0.299) | 0 of 9 |
| slow-stuffing | suspicious | recall | 40 | 0.550 (0.398-0.693) | 0.550 (0.398-0.693) | 0 of 40 |
| same-country-new-device | suspicious | recall | 40 | 0.350 (0.221-0.505) | 0.350 (0.221-0.505) | 0 of 40 |
| sim-swap | suspicious | recall | 40 | 1.000 (0.912-1.000) | 1.000 (0.912-1.000) | 0 of 40 |
| recovery-abuse | suspicious | recall | 40 | 1.000 (0.912-1.000) | 1.000 (0.912-1.000) | 0 of 40 |
| traveler | legitimate | false positive rate | 40 | 0.700 (0.546-0.819) | 0.700 (0.546-0.819) | 0 of 40 |
| shift-worker | legitimate | false positive rate | 40 | 0.150 (0.071-0.291) | 0.150 (0.071-0.291) | 0 of 40 |
| fat-finger | legitimate | false positive rate | 40 | 1.000 (0.912-1.000) | 1.000 (0.912-1.000) | 0 of 40 |
| new-phone | legitimate | false positive rate | 40 | 1.000 (0.912-1.000) | 1.000 (0.912-1.000) | 0 of 40 |

Model: llama3.2:3b (digest a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72) through Ollama at http://ollama:11434, one request at a time. Hardware: linux/arm64, 14 CPUs, the machine that ran this command.

| Latency of the model step | |
| --- | --- |
| p50 | 2.183s |
| p95 | 3.345s |

The model raised 0 of 620 logins, and 0 of those were suspicious. 0 responses were refused by the strict check and 4 requests failed; both count as no advice.
