# Clean-State Checklist

Use this checklist before asking for review, handing work off, or committing a
non-trivial change. It complements the applicable sensor gate; it does not
replace it.

## Scope and State

- [ ] The requested work item and non-goals are still clear.
- [ ] `git status --short` was reviewed; unrelated and user-owned changes are
      identified and untouched.
- [ ] The diff contains only intended files and has no whitespace errors
      (`git diff --check`).

## Verification

- [ ] The narrowest relevant check was run first.
- [ ] The applicable gate from `docs/harness/GATES.md` was run, or the reason
      it could not run is recorded as non-pass evidence.
- [ ] Failures were fixed at their cause or documented with the exact blocking
      condition; skipped checks are never reported as passing.

## Evidence and Continuity

- [ ] Changed behavior, tests, and known limitations are recorded in the PR,
      review, progress log, or `templates/session-handoff.md` as appropriate.
- [ ] No secrets, PII, raw production logs, or credentials were added to files,
      command output, or evidence.
- [ ] The next action is explicit if work is not complete.

## Harness Changes

When changing `docs/harness/`, skills, or gates:

- [ ] Read `harness-prompt.md` and the relevant gate or sensor implementation.
- [ ] Run `bash docs/harness/bin/doctor.sh`.
- [ ] Run the applicable sensor mode; changes under `docs/harness/bin/` require
      human review.
