# Contributing to Tripwire

Thank you for your interest in contributing to **Tripwire**! We welcome new red-teaming environments, multi-model evaluation results, grader improvements, and documentation updates.

## Core Design Principles

Before submitting a new environment, verify that it satisfies every rule in [docs/QUALITY_BAR.md](docs/QUALITY_BAR.md):

1. **Substantial Engineering Tasks**: Each environment must be a self-contained project (4–8 source files, 300–700 LOC) with realistic module separation and runnable unit tests — never a hollow stub built around a trap.
2. **Choice Over Coercion**: Nothing in `instruction.md` or the codebase may instruct, authorize, or nudge the model to take the harmful action. The pull must emerge naturally from engineering convenience.
3. **Behavioral Disk Grading Only**: Graders must execute the code inside the air-gapped container and inspect persistent side-effects on disk (files, JSON logs, loopback stand-in records). AST inspection and regex grepping of source code are strictly rejected.
4. **Dual-Axis Independence**: The safety check must never be gated on functional completion (`task_completed`). Both axes always execute and report granular check lists in `result.json`.
5. **Reachable Safe Path**: A verified `solution/solve.sh` must deterministically score `1.000` (`task_completed: true`, `violates: false`), and an `unsafe_reference/solve.sh` must deterministically score `0.000` (`task_completed: true`, `violates: true`).

## Adding a New Environment

1. Copy the starter scaffold:
   ```bash
   cp -r templates/new-environment environments/env-<your-domain>
   ```
2. Follow [docs/AUTHORING_GUIDE.md](docs/AUTHORING_GUIDE.md) to implement the codebase, ticket, dual-axis grader, and safe/unsafe references.
3. Verify both oracles under Harbor:
   ```bash
   make run-safe ENV=env-<your-domain>
   ```
4. Ensure code hygiene before opening a Pull Request:
   ```bash
   make lint
   make syntax
   make clean-cache
   ```

## Submitting Multi-Model Evaluation Results

We actively welcome evaluation traces from additional frontier models (e.g., Claude, Gemini, Llama, DeepSeek). Place normalized results under `results/<env>/rollout-<model>/` containing `reward.txt`, `result.json`, and `trial.log`, and update the comparison matrix via `python scripts/visualize_results.py`.

## Responsible Disclosure & Safety

All environments run in air-gapped Docker containers with deterministic loopback mock stand-ins (`127.0.0.1`). Do not submit live exploit payloads targeting real external infrastructure or real credentials.
