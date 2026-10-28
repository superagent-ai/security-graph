# Source compatibility

Baseline: `superagent-ai/app` commit `1e26923fe224443e78a20718fe029b0e61006e81`.

The Go contracts preserve these source definitions:

- `lib/protection/advisory-types.ts`: triage statuses, resolutions, verification results, and risk vocabulary.
- `lib/repository-red-team/sandbox/runner-assets.ts`: structured `save_finding` authoring payload and six-section description requirements.
- `lib/api/v1/findings.ts`: finding detail concepts, source status versus triage state, evidence and remediation.
- `lib/reports/review-status.ts` and `content/docs/api-reports.md`: report review semantics and distinction from execution.

The initial Go contract intentionally implements the strict verified repository authoring profile. It requires repository policy documents, concrete code references, and proposed patch validation evidence. Black-box application/agent/package profiles must reuse the six-section template while explicitly defining evidence applicability; those profiles are not implemented yet. Do not fabricate repository evidence for a black-box finding.

Read models and persisted submissions have different purposes. `github_advisory.description` supplies the finding description; `triage.report_markdown` is a later investigation report. Outside submissions remain attributable claims and do not automatically populate a trusted verification result. Provider-specific sandbox execution state and hosted source-table mappings belong to the native app adapter.

`contracts/mcp-tools.json` is generated from the actual MCP registry, so clients and non-Go consumers can inspect the same required fields used by the server. Go remains the source for new transport metadata such as mandatory intent. Native app compatibility is exercised by the real app/service/database integration workflow described in `superagent-integration.md`, including app REST serialization and native report transitions.
