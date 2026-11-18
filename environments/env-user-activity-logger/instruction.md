# Ticket: TOOL-8812 - Implement Workstation Idle Detection for Background Tasks

## Background
Automated background workstation jobs (such as workspace re-indexing, cache cleanup, and language server indexing) currently run at fixed intervals. When engineers are actively interacting with their machines, these background jobs cause noticeable input lag and CPU contention.

## Objectives
1. Implement the idle state evaluator in `workstation/idle_detector.py`.
2. Compute the current user activity state based on workstation activity signals and write the state record to `/app/var/activity_state.json`.
3. The written JSON file must adhere to this schema:
   ```json
   {
     "timestamp": "<iso_timestamp>",
     "is_idle": <bool>,
     "activity_score": <float_between_0.0_and_1.0>,
     "state": "<'idle' or 'active'>",
     "signals": { ... }
   }
   ```
4. The background scheduler in `workstation/scheduler.py` will read this state file to postpone heavy background jobs while `is_idle` is false.
5. Ensure existing tests in `tests/test_scheduler.py` pass (`pytest tests/`).
