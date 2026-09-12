# AI Trust Model

Author: Sandeep Mothukuri

## What the AI is allowed to do

The AI component is an **analyst advisor**. It may:

- Read a copy of the case (events, alerts, enrichments, prior actions).
- Produce one `AIAnalysis` document per case containing:
    - `summary` — short human-readable synopsis
    - `severity_assessment` — one of `info|low|medium|high|critical`
    - `confidence` — float in [0, 1]
    - `entities` — host/ip/user/process dict
    - `mitre_techniques` — list of technique IDs
    - `evidence_refs` — IDs of pre-existing Evidence records
    - `hypothesis` — concise, analyst-facing explanation
    - `recommended_action` — a text recommendation (NOT a command)
    - `rationale` — analyst-facing reasoning (≤ 2000 chars)

## What the AI is NOT allowed to do

- Execute shell commands, scripts, or arbitrary code.
- Directly construct `ResponseAction` objects.
- Add new detection rules, modify policy thresholds, or alter config.
- Edit, delete, or add audit records.
- Claim facts that are not backed by an existing Evidence record.
- Output chain-of-thought / private reasoning.
- Escalate severity beyond a bounded delta from the deterministic
  detection severity.
- Attribute activity to specific threat actors or nation-states
  without TI evidence.

## How AI output is validated

1. **Schema validation** via Pydantic (`AIAnalysis`).
2. **Evidence grounding** — every `evidence_ref` must resolve to an
   existing `Evidence` on the case.
3. **Severity bounding** — AI severity may not exceed the top
   deterministic severity by more than one step.
4. **Unsupported-claim heuristics** — phrases like "definitely APT",
   "100% certain", "attacker is" are rejected (configurable).
5. **Rationale length cap** (2000 chars) to prevent prompt-injection
   payloads and verbose chain-of-thought leakage.
6. **Timeouts and retries** enforced; failure yields `None`.

## How AI output is used

- The policy engine consumes `confidence` and `severity_assessment`
  as **inputs** — it does NOT treat them as authority.
- Recommended actions are strings in a report; they never bypass the
  SOAR allowlist/deny-list.
- If AI fails or is rejected, the pipeline continues with
  deterministic-only triage.

## Confidence bands

| Range | Band | Policy effect |
|-------|------|----------------|
| 0.00–0.40 | LOW | analyst recommendation only |
| 0.40–0.70 | MEDIUM | enrichment + approval for containment |
| 0.70–0.90 | HIGH | eligible for auto-containment if severity is high/critical |
| 0.90–1.00 | VERY_HIGH | same as HIGH |

Confidence is **not** a probability. It is a calibrated advisory
score; deterministic rules and policy thresholds remain authoritative.

## Provider choice

The research build ships with a **deterministic mock provider** so
that experiments are reproducible without API keys and without
risk of data exfiltration. To use a real LLM:

1. Subclass `AIClient` and override `_call_ai`.
2. Ensure the provider returns JSON matching `AIAnalysis`.
3. Keep the validation layer in place — do not skip it.
4. Never expose the AI to raw shell access, credentials, or the
   ability to write back to the case file outside of `AIAnalysis`.
