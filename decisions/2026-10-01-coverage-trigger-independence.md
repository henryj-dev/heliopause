# Who may trigger the coverage screen

This records a decision not to build something, and why, so the next person asking the same question
starts from the measurement rather than from the idea.

**Nothing in this document names a host, an address, or a repository.** The argument is about roles,
and roles are what make it true; the names would add nothing and this repository is published.

## The problem that raised the question

The coverage screen is periodic on purpose. Periodic rather than once-after-apply is what turns it
into compromise detection: a host whose rules were changed underneath it starts failing there without
anything in the fleet reporting a change.

It was scheduled hourly. Measured over fourteen days, **22% of those slots produced a run** — median
gap 4.8 hours. The same schedule mechanism delivered 104% for a twice-daily workflow in the same
place and 100% for weekly ones, so the loss tracks the cron's *frequency*, not the repository and not
the account. Creation was the missing step, not execution: the queue wait between a run being created
and a job starting was normally a tenth of a minute.

The cadence was lowered to four times a day, which is at or above what the hourly schedule was
actually delivering. That is everything the hosted scheduler can be made to do. **A tighter or more
predictable cadence requires a trigger outside it** — and that is the question this document answers.

## The shape of the proposal

A timer on a host we control, calling the workflow-dispatch API on a schedule we choose. It needs a
credential that can start workflow runs in the policy repository, stored on that host.

### Which host

| Role | Trust | Verdict |
|---|---|---|
| The shared CI runner | Deliberately **untrusted** — no mesh, no policy, no agent, no inbound | Rejected outright. Putting repository-write credentials on it is the opposite of why it is untrusted |
| **The manager host** | Inside the trust boundary; the source of publishing authority | The only real candidate |
| A gateway | Inside the boundary, but its role is relaying and resolution | Mixing a CI trigger into it muddies a role |
| An operator workstation | Trusted, but **not always on** | Cannot guarantee a cadence, which is the whole point |

So the candidate is the manager host. Note what that already means: it is the host whose publishing
authority the coverage screen exists to check.

### Which credential

Scope it as narrowly as the platform allows — one repository, the single permission needed to start a
workflow run, nothing for repository contents. Store it `0600` and hand it to the timer as a
credential rather than an environment variable, because environment variables leak into process
listings and the journal.

Two forms, and neither is good:

- **A user-owned token.** This repository already rejected that reasoning once, when it chose a
  read-only deploy key for the coverage workflow's checkout: a user token carries whatever its maker
  can reach, dies quietly when they leave, and has an expiry somebody has to remember. Nothing here
  overturns that.
- **An application identity.** Not tied to a person, and scoped per installation. But its signing key
  does not expire. The hour-long tokens it mints are short *only for whoever holds that key* — an
  intruder holding it mints them too. This trades person-dependence for expiry. It is an exchange,
  not an improvement.

**Neither gives a short-lived secret, and that is structural.** An unattended periodic trigger
requires a credential that sits somewhere all the time. No scoping removes that cost.

## What a compromise of that host would gain

Assume the narrow scope above.

1. **Runs on demand, as often as wanted.** The coverage workflow writes its result to the policy
   repository on every run. An intruder does not choose the contents — the probes produce those — but
   they control *when a commit happens*, and repeated runs push older results out of recent history.
   That history is the failure record the design asks for, so **diluting it dilutes the evidence.**
2. **Not only this workflow.** Permission to start workflow runs is not permission to start *one*
   workflow. Every dispatchable workflow in that repository becomes reachable, including the one that
   proposes policy to the manager. The platform offers no finer split.
3. **Cancelling runs is the same permission.** An intruder can quietly cancel the runs that would
   have measured their own activity.

Now the part that decides it. A compromised manager host can **already** publish policy — that is
what being inside the trust boundary means, and this credential adds nothing there. **Exactly one
thing is new: control over the measurement and its history.** And that measurement is the only
reading on the screen that does not come from the fleet talking about itself. It exists to catch the
manager lying.

Putting its trigger on the manager host **hands the detector's power switch to the thing being
watched.** Today that switch sits with the hosted scheduler. A slow scheduler and a watched party
holding the switch are not the same kind of problem, and the second is worse than the first.

## Decision

**Do not build it.** What is gained is a predictable cadence. What is lost is independence, which is
the reason the screen exists. Once the measurement arrives reliably at four times a day, the remaining
difference is six hours versus one, and that is not worth the trade.

Cheaper things first, in order:

1. **Re-measure the arrival rate after the cadence change has had two weeks.** If four a day arrives
   at roughly 100%, this proposal is unnecessary. If it does not, the next step is **twice a day,
   which is measured** — not a shorter interval, which is the direction that caused the loss.
2. **Make a stale observation say so.** The real risk of a slow measurement is not the slowness; it is
   reading an old green cell as current. The screen now counts a passing-but-stale check separately
   from a passing one, and derives the staleness window from the publishing cadence rather than from a
   number somebody picked. That removes the false reassurance even when the cadence cannot be raised.
3. If a tighter cadence is still wanted after both, the next design question is **a trusted host that
   is not the manager** — separating the watched party from the trigger is the whole point. Whether
   such a host exists in the fleet has not been checked.

### If it is built anyway

Minimum conditions: an application identity rather than a user token; one repository and one
permission; the secret delivered as a credential, not an environment variable; every dispatch logged
with which timer fired it and when; and **that log kept somewhere other than the manager host.**
Without the last one, point 3 above — quiet cancellation — is invisible.

## When to revisit

The two-week re-measurement, and whether the stale-observation change proved sufficient in practice.
Both are prerequisites, not alternatives: if the measurement arrives reliably and a stale cell is
visibly stale, the problem this proposal solves has mostly gone away.
