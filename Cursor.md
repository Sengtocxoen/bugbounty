# Cursor Project Notes

## What Happened In The Project

- The repository expanded from a single automation flow to a broader toolkit.
- The `tools/web_hacking_2025` suite was added to cover technique-based testing.
- A unified runner (`tools/run_all.py`) now chains deep scans and techniques for a single target or a list of targets.
- Reporting remains HTML-first, with results grouped by scan type for easier review.

## What The Project Should Focus On

- **Repeatability:** predictable outputs and configs for consistent runs.
- **Safety:** default to authorized, low-risk checks and make high-risk steps explicit.
- **Clarity:** consistent logging, report structure, and data formats across tools.
- **Extensibility:** make it easy to add new checks without duplicating logic.
- **Performance:** avoid redundant recon and keep scans efficient.

## How To Improve The Code

- **Config unification:** consolidate multiple config formats into one schema and validate it early.
- **Shared utilities:** extract common HTTP, parsing, and rate-limit logic into a single library.
- **Result schema:** standardize findings with severity, evidence, and remediation fields.
- **Test coverage:** add tests for config parsing, target normalization, and report rendering.
- **Error handling:** enforce consistent exceptions, retries, and timeouts.
- **Documentation:** add minimal usage examples for each major module and the unified runner.

