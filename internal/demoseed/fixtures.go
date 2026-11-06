package demoseed

import (
	"fmt"
	"strings"

	"github.com/superagent-ai/security-graph/pkg/contracts"
)

type agent struct{ name, reportType string }

var agents = []agent{
	{"pr-review-bot", "repository"}, {"codeql-scanner", "repository"},
	{"dependency-auditor", "package"}, {"web-red-teamer", "web_app"},
	{"api-red-teamer", "web_app"}, {"agent-red-teamer", "agent"},
	{"cloud-posture-bot", "repository"}, {"secrets-scanner", "repository"},
}

type scenario struct{ title, typeID, cwe, impact, details, proof, remediation string }

var scenarios = []scenario{
	{"Cross-tenant invoice access", "idor", "CWE-639", "A tenant could read another tenant's invoice.", "The illustrative invoice handler trusts an invoice ID without checking tenant membership.", "Tenant A requests tenant B's fixture invoice; the simulated response contains B's fixture row.", "Load the invoice through a tenant-scoped query and reject missing membership."},
	{"SQL injection in the report filter", "sql_injection", "CWE-89", "An attacker could influence a database query.", "The illustrative report filter concatenates an untrusted string into a query.", "The simulated hostile filter alters the fixture query plan instead of remaining a bound parameter.", "Use parameterized queries and validate the accepted filter fields."},
	{"Outbound URL bypasses destination validation", "ssrf", "CWE-918", "The service could contact an unintended internal destination.", "The illustrative webhook tester accepts a URL without enforcing destination and redirect policy.", "A simulated destination resolving to a private fixture address passes the URL guard.", "Validate resolved destinations, constrain redirects, and enforce an outbound allowlist."},
	{"Stored script content in an audit annotation", "stored_xss", "CWE-79", "A stored annotation could execute in a reviewer's browser.", "The illustrative annotation renderer treats untrusted annotation text as HTML.", "A harmless simulated marker reaches the fixture's executable HTML sink.", "Render annotation content as text or sanitize with a strict allowlist."},
	{"Archive extraction escapes the workspace", "path_traversal", "CWE-22", "An archive member could overwrite files outside its workspace.", "The illustrative extraction routine joins archive paths without verifying the normalized destination.", "A simulated parent-directory archive member resolves beyond the temporary fixture root.", "Reject absolute and escaping paths after normalization and verify each extraction destination."},
	{"Retrieved ticket content overrides agent policy", "indirect_prompt_injection", "CWE-1427", "Untrusted retrieved text could steer an agent's authorized actions.", "The illustrative support agent mixes retrieved ticket text with trusted tool instructions.", "A synthetic ticket asks the fixture agent to ignore policy; the simulated trace follows that instruction.", "Separate trusted instructions from retrieved data and enforce authorization at the tool boundary."},
	{"Refund tool exceeds the agent's delegated access", "excessive_agency", "CWE-862", "An agent could act outside the initiating user's allowed scope.", "The illustrative refund tool uses a broad service identity without checking the caller's delegation.", "The simulated restricted-user request reaches a refund tool operation outside that user's scope.", "Bind each tool invocation to the initiating principal and enforce the permitted resources and operations."},
	{"Diagnostic response includes a fixture secret", "sensitive_data_exposure", "CWE-200", "Diagnostic responses could disclose sensitive configuration.", "The illustrative error serializer includes configuration values in an API response.", "The simulated response contains DEMO_NOT_A_REAL_SECRET; no live credential is present.", "Return an opaque error reference and redact sensitive fields before serialization."},
	{"Webhook retry skips authentication", "authentication_bypass", "CWE-287", "An unauthenticated retry could be processed as a trusted event.", "The illustrative retry path bypasses the signature verification applied to initial deliveries.", "A simulated unsigned retry is accepted by the fixture branch while the initial delivery is rejected.", "Run the same authentication checks before every delivery or retry is processed."},
	{"User input reaches a process invocation", "command_injection", "CWE-78", "Untrusted input could alter a process invocation.", "The illustrative build hook composes a shell command from an unvalidated job argument.", "A simulated metacharacter marker changes the fixture command tokenization; no command is executed.", "Avoid shell interpolation and pass validated arguments directly to the process API."},
}
var assetNames = []string{"payments-api", "checkout-web", "ledger-service", "auth-gateway", "webhook-ingest", "billing-worker", "support-agent", "search-api", "notification-service", "artifact-registry", "analytics-worker", "customer-portal", "policy-engine", "document-agent", "integration-gateway", "inventory-service", "audit-store", "refund-worker", "upload-service", "scheduler"}

func assetSlug(i int) string { return fmt.Sprintf("%s-%03d", assetNames[i%len(assetNames)], i) }
func syntheticFinding(i int, assetID string) (contracts.Submission, string) {
	s := scenarios[i%len(scenarios)]
	severity := []string{"critical", "high", "high", "medium", "medium", "low"}[i%6]
	title := fmt.Sprintf("[DEMO] %s · %05d", s.title, i+1)
	path := fmt.Sprintf("demo/%s/handler.go", strings.TrimPrefix(assetID, "demo/"))
	marker := "SYNTHETIC DEMO DATA: illustrative evidence only; no assessment, exploit, or patch validation was executed. "
	impact, details, proof, remediation := marker+s.impact, marker+s.details, marker+s.proof, marker+s.remediation
	policy := contracts.PolicyVerification{DocsReviewed: []contracts.PolicyDocument{{File: "DEMO_SECURITY_POLICY.md", RelevantExcerpt: "Demo tenants, users, and delegated agents must stay within their authorized resources.", Interpretation: "This fictional fixture illustrates a violation of the demo policy."}}, InScope: true, Conclusion: "Synthetic example of a policy violation; not a verified vulnerability."}
	patch := contracts.ProposedPatch{Summary: "[DEMO] " + s.remediation, Diff: fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -10 +10 @@\n-demoHandle(input)\n+demoHandleAuthorized(input, principal)\n", path, path), Files: []string{path}, Validation: contracts.PatchValidation{Tests: []contracts.ValidationCommand{{Command: "demo-fixture-check --scenario " + s.typeID, Result: "SYNTHETIC expected result: out-of-scope input is rejected. This command was not executed and does not claim real patch validation."}}}}
	description := strings.Join([]string{"## Impact\n" + impact, "## Details\n" + details, "## Policy Verification\n" + policy.Conclusion, "## Code References\n" + path + ":10-14 (fictional source file)", "## PoC\n" + proof, "## Remediation\n" + remediation}, "\n\n")
	return contracts.Submission{ID: fmt.Sprintf("DEMO-%06d", i+1), Title: title, Severity: severity, CWEIDs: []string{s.cwe}, AffectedFiles: []string{path}, Summary: marker + s.title, Impact: impact, Details: details, Proof: proof, ExploitPreconditions: []string{"A synthetic demo account and isolated fictional fixture environment."}, ReproductionSteps: []string{"Load the fictional " + s.typeID + " fixture.", "Simulate the illustrative request or agent interaction.", "Compare the synthetic result with DEMO_SECURITY_POLICY.md; no real target was tested."}, PolicyVerification: policy, FalsePositiveAnalysis: "This is intentionally generated dummy data. No independent verification or real security conclusion is asserted.", CodeReferences: []contracts.CodeReference{{File: path, LineStart: 10, LineEnd: 14, Symbol: "demoHandle", Excerpt: "demoHandle(input)", Reason: "Fictional example used to exercise the shared finding template."}}, Remediation: remediation, ProposedPatch: patch, GitHubAdvisory: contracts.Advisory{Summary: title, Description: description, Severity: severity, CWEIDs: []string{s.cwe}, Vulnerabilities: []contracts.Vulnerability{{Package: contracts.Package{Ecosystem: "Go", Name: "example.invalid/demo/" + assetSlug(i)}, VulnerableVersionRange: "0.0.0-demo"}}}}, s.typeID
}
