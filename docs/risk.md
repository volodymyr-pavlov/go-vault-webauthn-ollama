# The risk engine and its evaluation

Every login gets a score from 0 to 100. Fixed rules compute the score from signals. A local model can argue for a
stricter decision, but it can never argue for a looser one.

## The signals and the score

| Signal                                | Points                      |
| ------------------------------------- | --------------------------- |
| A new device                          | 25                          |
| A factor enrolled within a day        | 15                          |
| Failed attempts in the last ten minutes, of the account or from the address | 5 each, up to 25 |
| Wrong codes since the last good one   | 5 each, up to 15            |
| An unusual hour for the account       | 10                          |
| An impossible travel since the last login | 40                      |
| A shared address: at least 5 different accounts tried the same address in the last hour | 10 |

The signals come from the sessions of the user, which form the login history, and from the user row. The service counts
a new device only after the account has logged in once. The passkey and TOTP login handlers compute the shared address
from the sessions of the address. Credential stuffing sets this signal, and so does an office or a mobile carrier. The
score is capped at 100.

In the code, `ai.Signals` is one `uint16`. Five flag bits hold the new device, the recent enrollment, the unusual hour,
the impossible travel and the shared address. Three more bits count the failed attempts, which stop at 5. Two more bits
count the wrong TOTP codes, which stop at 3. The advisor sees the names of the set signals and the two counts.

## The decision

| Score   | Level  | Decision                                                      |
| ------- | ------ | ------------------------------------------------------------- |
| 0 to 29 | low    | Allow.                                                        |
| 30 to 69| medium | Limit: a sensitive action needs a fresh authentication first. |
| 70 up   | high   | Refuse the login.                                             |

The model can turn allow into limit, and limit into review. It can never turn any decision into refuse, and it can never
turn any decision into allow. A refused login stays refused.

## The model

The model is `llama3.2:3b`, and the service runs it through Ollama. The service sends a fixed template of typed fields:
a keyed pseudonym, a country, a four-hour bucket of the day, the factor, the names of the signals and two counts. The
prompt holds nothing that a user typed, so there is nothing to inject into it.

Ollama has a JSON schema for the response, and the service checks the response again, strictly. The levels and the
reasons are closed sets, the summary has at most 200 bytes, and the service accepts no unknown field.

Ollama has no authentication of its own, and it has no published port. The service does not start without Ollama. At
start-up it checks the digest of the model. It limits the size of a request, runs at most two requests at once and gives
up after a timeout. After three failures in a row, a breaker stops the calls for thirty seconds. The service never logs
a prompt or a raw response.

When the model is late, down or wrong, the rules decide alone.

## Evaluation

The dataset has 700 synthetic logins that a seed produces: 300 from a baseline mix and 50 from each of eight hard
scenarios. In the baseline, four in five logins are legitimate. The suspicious logins are bursts of failures, new
devices at odd hours, impossible travel, wrong codes, and one weak case that the rules let through: a new credential
with a failed code or two. The hard scenarios are slow credential stuffing, a new device in the same country, a SIM
swap, recovery abuse, a legitimate traveler, a shift worker, a mistyped code and a new phone. The labels are true by
construction, so the figures say nothing about real traffic.

`make evaluate` writes the report. With a model, it needs a warm Ollama; the target passes `-timeout 3m`. `EVALUATE_ARGS` replaces
that, for example `EVALUATE_ARGS="-per 60"`. The flags `-per` (logins for each hard scenario) and `-timeout` exist. The report of the last run is in [evaluation.md](evaluation.md), and the
dataset is in [dataset.csv](dataset.csv). Every share in the report has a 95 percent Wilson interval.

The last run asked `llama3.2:3b` (digest `a80c4f17…`) about every login, one request at a time. It ran on the CPU of a
linux/arm64 machine with 14 CPUs and nothing else running. The data had 620 logins: 300 baseline logins and 40 for each
hard scenario. Of the requests, 4 failed or timed out, and they count as no advice. The model raised none of the 620
logins, so the recall and the false positive rate are the same with and without it. The model step took 2.18 seconds at
the median and 3.35 seconds at the 95th percentile.

An earlier run on a busy machine failed 514 of 620 requests, because the circuit breaker opened. The team discarded its
figures. A model run needs a quiet machine.

| Part of the data | Decider              | Recall              | False positive rate |
| ---------------- | -------------------- | ------------------- | ------------------- |
| Baseline mix     | Rules alone          | 0.855 (0.747-0.922) | 0.000 (0.000-0.016) |
| Baseline mix     | Rules with the model | 0.855 (0.747-0.922) | 0.000 (0.000-0.016) |
| Hard scenarios   | Rules alone          | 0.725 (0.651-0.788) | 0.713 (0.638-0.777) |
| Hard scenarios   | Rules with the model | 0.725 (0.651-0.788) | 0.713 (0.638-0.777) |

## Known weaknesses of the rules

The hard scenarios show where the rules fail. The false positive rate is the share of legitimate logins that the rules
flag. The recall is the share of suspicious logins that the rules flag.

| Scenario                 | Metric              | Rules alone         | Rules with the model |
| ------------------------ | ------------------- | ------------------- | -------------------- |
| traveler                 | false positive rate | 0.700 (0.546-0.819) | 0.700 (0.546-0.819)  |
| fat-finger               | false positive rate | 1.000 (0.912-1.000) | 1.000 (0.912-1.000)  |
| new-phone                | false positive rate | 1.000 (0.912-1.000) | 1.000 (0.912-1.000)  |
| shift-worker             | false positive rate | 0.150 (0.071-0.291) | 0.150 (0.071-0.291)  |
| slow-stuffing            | recall              | 0.550 (0.398-0.693) | 0.550 (0.398-0.693)  |
| same-country-new-device  | recall              | 0.350 (0.221-0.505) | 0.350 (0.221-0.505)  |
| sim-swap                 | recall              | 1.000 (0.912-1.000) | 1.000 (0.912-1.000)  |
| recovery-abuse           | recall              | 1.000 (0.912-1.000) | 1.000 (0.912-1.000)  |

The rules flag a legitimate traveler, a mistyped code and a new phone too often. They miss slow credential stuffing and
a new device in the same country too often. The model did not repair any of these cases, because it raised none of the
620 logins. So on this data the model step adds about two seconds of delay and no recall, and the numbers do not justify
it. The synthetic labels and the fixed prompt may explain part of this result. The data supports no claim about accuracy
in production.

The design holds either way. The rules decide, the model can only add verification, and the service is complete without
the model.
