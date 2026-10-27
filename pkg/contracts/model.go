// Package contracts preserves Superagent's finding and report vocabulary.
package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid_request")

const (
	New      = "new"
	Triaging = "triaging"
	InReview = "in_review"
	Resolved = "resolved"
)

type Triage struct {
	Status             string          `json:"status"`
	Resolution         *string         `json:"resolution"`
	Summary            *string         `json:"summary"`
	Recommendation     *string         `json:"recommendation"`
	ReportMarkdown     *string         `json:"report_markdown"`
	VerificationStatus *string         `json:"verification_status"`
	Evidence           json.RawMessage `json:"evidence"`
	StartedAt          *time.Time      `json:"started_at"`
	CompletedAt        *time.Time      `json:"completed_at"`
}

type CodeReference struct {
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol,omitempty"`
	Excerpt   string `json:"excerpt"`
	Reason    string `json:"reason"`
}
type ValidationCommand struct {
	Command string `json:"command"`
	Result  string `json:"result"`
}
type PatchValidation struct {
	Tests []ValidationCommand `json:"tests"`
}
type ProposedPatch struct {
	Summary    string          `json:"summary"`
	Diff       string          `json:"diff"`
	Files      []string        `json:"files"`
	Validation PatchValidation `json:"validation"`
}
type PolicyDocument struct {
	File            string `json:"file"`
	RelevantExcerpt string `json:"relevant_excerpt"`
	Interpretation  string `json:"interpretation"`
}
type PolicyVerification struct {
	DocsReviewed               []PolicyDocument `json:"docs_reviewed"`
	InScope                    bool             `json:"in_scope"`
	ContradictedByPolicy       bool             `json:"contradicted_by_policy"`
	DocumentedIntendedBehavior bool             `json:"documented_intended_behavior"`
	Conclusion                 string           `json:"conclusion"`
}
type Advisory struct {
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	CWEIDs          []string        `json:"cwe_ids"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}
type Vulnerability struct {
	Package                Package  `json:"package"`
	VulnerableVersionRange string   `json:"vulnerable_version_range"`
	PatchedVersions        []string `json:"patched_versions,omitempty"`
	VulnerableFunctions    []string `json:"vulnerable_functions,omitempty"`
}

// Submission is the existing repository save_finding authoring contract.
// Transport metadata (intent, idempotency, actor) never lives in this model.
type Submission struct {
	ID                    string             `json:"id"`
	Title                 string             `json:"title"`
	Severity              string             `json:"severity"`
	CWEIDs                []string           `json:"cwe_ids"`
	AffectedFiles         []string           `json:"affected_files"`
	Summary               string             `json:"summary"`
	Impact                string             `json:"impact"`
	Details               string             `json:"details"`
	Proof                 string             `json:"proof"`
	ExploitPreconditions  []string           `json:"exploit_preconditions"`
	ReproductionSteps     []string           `json:"reproduction_steps"`
	PolicyVerification    PolicyVerification `json:"policy_verification"`
	FalsePositiveAnalysis string             `json:"false_positive_analysis"`
	CodeReferences        []CodeReference    `json:"code_references"`
	Remediation           string             `json:"remediation"`
	ProposedPatch         ProposedPatch      `json:"proposed_patch"`
	GitHubAdvisory        Advisory           `json:"github_advisory"`
}

func ValidateIntent(intent string) error {
	n := utf8.RuneCountInString(strings.TrimSpace(intent))
	if n < 1 || n > 500 {
		return fmt.Errorf("%w: intent must contain 1 to 500 nonblank characters", ErrInvalid)
	}
	return nil
}
func ValidateResolution(status string, resolution *string) error {
	if status != New && status != InReview && status != Resolved {
		return fmt.Errorf("%w: manual status must be new, in_review, or resolved", ErrInvalid)
	}
	if status == Resolved && (resolution == nil || !oneOf(*resolution, "fixed", "accepted_risk", "false_positive", "wont_fix")) {
		return fmt.Errorf("%w: resolving requires fixed, accepted_risk, false_positive, or wont_fix", ErrInvalid)
	}
	return nil
}
func oneOf(v string, options ...string) bool {
	for _, option := range options {
		if v == option {
			return true
		}
	}
	return false
}
func nonempty(v string) bool { return strings.TrimSpace(v) != "" }
func stringList(v []string) bool {
	if len(v) == 0 {
		return false
	}
	for _, s := range v {
		if !nonempty(s) {
			return false
		}
	}
	return true
}

func (s *Submission) Validate() error {
	if !nonempty(s.Title) {
		s.Title = s.GitHubAdvisory.Summary
	}
	if !nonempty(s.Severity) {
		s.Severity = s.GitHubAdvisory.Severity
	}
	for _, field := range []struct{ name, value string }{{"id", s.ID}, {"title", s.Title}, {"summary", s.Summary}, {"impact", s.Impact}, {"details", s.Details}, {"proof", s.Proof}, {"false_positive_analysis", s.FalsePositiveAnalysis}, {"remediation", s.Remediation}, {"github_advisory.summary", s.GitHubAdvisory.Summary}, {"github_advisory.description", s.GitHubAdvisory.Description}} {
		if !nonempty(field.value) {
			return fmt.Errorf("%w: finding.%s is required", ErrInvalid, field.name)
		}
	}
	if !oneOf(s.Severity, "critical", "high", "medium", "low") {
		return fmt.Errorf("%w: invalid severity", ErrInvalid)
	}
	if !stringList(s.CWEIDs) || !stringList(s.GitHubAdvisory.CWEIDs) || !stringList(s.AffectedFiles) || !stringList(s.ExploitPreconditions) || !stringList(s.ReproductionSteps) {
		return fmt.Errorf("%w: CWE, affected_files, exploit_preconditions, and reproduction_steps must be nonempty", ErrInvalid)
	}
	for _, list := range [][]string{s.CWEIDs, s.GitHubAdvisory.CWEIDs} {
		for _, cwe := range list {
			if !strings.HasPrefix(cwe, "CWE-") || len(cwe) < 5 {
				return fmt.Errorf("%w: invalid CWE identifier", ErrInvalid)
			}
			for _, c := range cwe[4:] {
				if c < '0' || c > '9' {
					return fmt.Errorf("%w: invalid CWE identifier", ErrInvalid)
				}
			}
		}
	}
	if len(s.GitHubAdvisory.Vulnerabilities) == 0 {
		return fmt.Errorf("%w: affected products are required", ErrInvalid)
	}
	headings := map[string]bool{}
	for _, line := range strings.Split(s.GitHubAdvisory.Description, "\n") {
		headings[strings.ToLower(strings.TrimSpace(line))] = true
	}
	for _, h := range []string{"Impact", "Details", "Policy Verification", "Code References", "PoC", "Remediation"} {
		if !headings["## "+strings.ToLower(h)] {
			return fmt.Errorf("%w: description requires ## %s", ErrInvalid, h)
		}
	}
	p := s.PolicyVerification
	if len(p.DocsReviewed) == 0 || !nonempty(p.Conclusion) {
		return fmt.Errorf("%w: policy review documents and conclusion are required", ErrInvalid)
	}
	for _, d := range p.DocsReviewed {
		if !nonempty(d.File) || !nonempty(d.RelevantExcerpt) || !nonempty(d.Interpretation) {
			return fmt.Errorf("%w: incomplete policy document", ErrInvalid)
		}
	}
	if len(s.CodeReferences) == 0 {
		return fmt.Errorf("%w: code_references are required", ErrInvalid)
	}
	for _, r := range s.CodeReferences {
		if !nonempty(r.File) || r.LineStart < 1 || r.LineEnd < r.LineStart || !nonempty(r.Excerpt) || !nonempty(r.Reason) {
			return fmt.Errorf("%w: invalid code reference", ErrInvalid)
		}
	}
	patch := s.ProposedPatch
	if !nonempty(patch.Summary) || !nonempty(patch.Diff) || !stringList(patch.Files) || len(patch.Validation.Tests) == 0 {
		return fmt.Errorf("%w: patch and validation evidence are required", ErrInvalid)
	}
	for _, v := range patch.Validation.Tests {
		if !nonempty(v.Command) || !nonempty(v.Result) {
			return fmt.Errorf("%w: incomplete patch validation", ErrInvalid)
		}
	}
	b, _ := json.Marshal(s)
	if len(b) > 262144 {
		return fmt.Errorf("%w: finding exceeds 256 KiB", ErrInvalid)
	}
	return nil
}

type Finding struct {
	ID          string     `json:"id"`
	Object      string     `json:"object"`
	Kind        string     `json:"kind"`
	ReportID    string     `json:"report_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	CWEIDs      []string   `json:"cwe_ids"`
	Source      string     `json:"source"`
	Triage      Triage     `json:"triage"`
	Submission  Submission `json:"submission"`
}
type Report struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Type        string `json:"type"`
	Target      string `json:"target"`
	Source      string `json:"source"`
	Status      string `json:"status"`
	AgentStatus string `json:"agent_status"`
}

func ValidReportType(v string) bool { return oneOf(v, "repository", "web_app", "agent", "package") }

type Asset struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Locator string `json:"locator"`
}
type Relationship struct {
	SourceID   string `json:"source_id"`
	Type       string `json:"type"`
	TargetID   string `json:"target_id"`
	Provenance string `json:"provenance"`
	Revision   string `json:"revision,omitempty"`
}
