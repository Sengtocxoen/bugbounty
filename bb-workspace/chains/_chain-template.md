# Chain Map — [TARGET / PROGRAM NAME]

> AI Planning format. Each vulnerability is an Action node.
> Chain: Preconditions → Effects → next Action.
> Goal: find the shortest path from low primitives to Critical impact.

---

## Chain Overview

| Chain ID | Start Primitive | Final Effect | Combined Severity |
|----------|----------------|--------------|-------------------|
| C001 | | | |
| C002 | | | |

---

## Chain C001 — [Short Name]

```
Action: [Finding ID] — [Vulnerability Name]
  Preconditions: [What must be true to use this action]
  Effects:       [What new state/capability this produces]
  Chains into:   [Next action name]

Action: [Next Vulnerability / Step]
  Preconditions: [Effects from above + any additional conditions]
  Effects:       [New state produced]
  Chains into:   [Final impact or next step]

Action: [Final Impact]
  Preconditions: [Accumulated effects from chain]
  Effects:       [Attacker's ultimate capability]
  Chains into:   N/A — END OF CHAIN
```

**Full PoC HTTP Sequence:**
```
Step 1 — [Action name]
Request:

Response (key evidence):


Step 2 — [Action name]
Request:

Response (key evidence):

```

**Worst-case narrative:**
<!-- Realistic attacker scenario at scale -->

**Escalated severity:** [Critical / High] — [CVSS v4.0 vector if applicable]

**Finding IDs involved:** F001, F002, ...

---

## Unchained Primitives (could not chain yet)

| Finding ID | Primitive | Blocker |
|------------|-----------|---------|
| | | Missing precondition: |
| | | Missing precondition: |
