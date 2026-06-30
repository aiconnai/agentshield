# Harness Progress

This file is the public, repo-safe harness state summary. It intentionally avoids personal paths, local machine details, tokens, raw agent transcripts, and generated review output.

## Current status

- No active public harness task is recorded.
- Generated review artifacts belong under `docs/harness/reviews/` and are ignored by default except `.gitkeep`.
- Detailed per-run or local notes belong in ignored harness progress artifacts, not in committed history.

## Publication hygiene

Before publishing, verify that committed harness evidence does not contain:

- absolute local paths;
- raw model or tool transcripts;
- environment dumps;
- tokens, keys, or secrets;
- generated artifacts that are not needed for the public project contract.
