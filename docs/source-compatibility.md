# Source compatibility

Baseline: `superagent-ai/app` commit `1e26923fe224443e78a20718fe029b0e61006e81`.

The Go contracts preserve these source definitions:

- `lib/protection/advisory-types.ts`: triage statuses, resolutions, verification results, and risk vocabulary.
- `lib/repository-red-team/sandbox/runner-assets.ts`: structured `save_finding` authoring payload and six-section description requirements.
- `lib/api/v1/findings.ts`: finding detail concepts, source status versus triage state, evidence and remediation.
- `lib/reports/review-status.ts` and `content/docs/api-reports.md`: report review semantics and distinction from execution.

The shared external `submit_finding` contract extends the original verified repository authoring payload to support black-box assessments for every report type. `affected_files`, `code_references`, `proposed_patch`, and `policy_verification.docs_reviewed` are optional. Omission means evidence was unavailable, not that a patch was validated or a policy was verified. Supplied references and policy documents must be complete; a supplied patch still requires its summary, diff, files, and validation evidence. Existing complete repository submissions remain valid. This external attributed-claim contract does not change the App's native verified repository authoring requirements.

All submissions retain the six-section template, concrete PoC, reproduction steps, affected-product information, impact, false-positive analysis, policy conclusion, and remediation. If `code_references` is omitted, null, or empty, a nonblank `code_references_unavailable_reason` is required and its exact text must appear in the `Code References` section. If `policy_verification.docs_reviewed` is omitted, null, or empty, a nonblank `policy_verification.docs_unavailable_reason` is required and its exact text must appear in the policy conclusion. This makes unavailable evidence explicit in both the structured submission and its narrative; a heading alone or an unsupported policy assertion is insufficient. Existing complete source-assisted submissions do not need these reasons. Black-box PoCs can describe requests and responses, endpoint behavior, or agent interactions rather than source code. Do not fabricate repository evidence, package versions, policy reviews, or patch validation for a black-box finding.

Read models and persisted submissions have different purposes. `github_advisory.description` supplies the finding description; `triage.report_markdown` is a later investigation report. Outside submissions remain attributable claims and do not automatically populate a trusted verification result. Provider-specific sandbox execution state and hosted source-table mappings belong to the native app adapter.

`contracts/mcp-tools.json` is generated from the actual MCP registry, so clients and non-Go consumers can inspect the same required fields used by the server. Go remains the source for new transport metadata such as mandatory intent. Native app compatibility is exercised by the real app/service/database integration workflow described in `superagent-integration.md`, including app REST serialization and native report transitions.
