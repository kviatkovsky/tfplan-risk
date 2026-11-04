package aws

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// policyTypes maps resource types to the attribute holding a policy document.
var policyTypes = map[string]string{
	"aws_iam_policy":       "policy",
	"aws_iam_role_policy":  "policy",
	"aws_iam_user_policy":  "policy",
	"aws_iam_group_policy": "policy",
}

var attachmentTypes = []string{
	"aws_iam_role_policy_attachment",
	"aws_iam_user_policy_attachment",
	"aws_iam_group_policy_attachment",
	"aws_iam_policy_attachment",
}

// adminManagedPolicies are AWS managed policies equivalent to wildcard grants.
var adminManagedPolicies = map[string]rules.Severity{
	"AdministratorAccess": rules.SeverityCritical,
	"IAMFullAccess":       rules.SeverityHigh,
	"PowerUserAccess":     rules.SeverityHigh,
}

// privilegedServices are services where "<svc>:*" amounts to privilege
// escalation or control over other identities and keys.
var privilegedServices = []string{"iam", "sts", "organizations", "kms"}

var readVerbPrefixes = []string{
	"Get", "List", "Describe", "Head", "BatchGet", "Query", "Scan", "Search", "Lookup", "Select", "View", "Check",
}

// IAMWildcard flags IAM policies that grant wildcard permissions.
type IAMWildcard struct{}

// NewIAMWildcard returns the rule.
func NewIAMWildcard() *IAMWildcard { return &IAMWildcard{} }

// Meta implements rules.Rule.
func (r *IAMWildcard) Meta() rules.Meta {
	return rules.Meta{
		ID:       "TPR-SEC-002",
		Title:    "IAM policy grants wildcard permissions",
		Category: rules.CategorySecurity,
		Severity: rules.SeverityCritical,
		Description: "The plan adds an Allow statement that grants overly broad permissions: " +
			"Action \"*\" (critical with Resource \"*\"), NotAction, iam:PassRole on any role, " +
			"\"<service>:*\" on Resource \"*\", or write actions on Resource \"*\". Attaching " +
			"AdministratorAccess, PowerUserAccess or IAMFullAccess is reported too. " +
			"Only statements that are new in this plan are reported.",
		Checks: []string{
			"aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy, aws_iam_group_policy: policy (JSON document)",
			"aws_iam_role: inline_policy[*].policy, managed_policy_arns",
			strings.Join(attachmentTypes, ", ") + ": policy_arn",
		},
		Example: `resource "aws_iam_policy" "ci" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}`,
		Suggestion: "Grant only the actions and resources the workload needs (least privilege). Use IAM " +
			"Access Analyzer policy generation from CloudTrail activity to derive a minimal policy, and " +
			"scope iam:PassRole to specific role ARNs with an iam:PassedToService condition.",
	}
}

// Evaluate implements rules.Rule.
func (r *IAMWildcard) Evaluate(c plan.Change) []rules.Finding {
	if c.Action != plan.ActionCreate && c.Action != plan.ActionUpdate && c.Action != plan.ActionReplace {
		return nil
	}
	var out []rules.Finding
	if attr, ok := policyTypes[c.Type]; ok {
		out = append(out, r.documentFindings(c, []any{attr})...)
	}
	if c.Type == "aws_iam_role" {
		list, _ := c.After["inline_policy"].([]any)
		for i := range list {
			out = append(out, r.documentFindings(c, []any{"inline_policy", i, "policy"})...)
		}
		out = append(out, r.attachmentFindings(c, "managed_policy_arns")...)
	}
	if slices.Contains(attachmentTypes, c.Type) {
		out = append(out, r.attachmentFindings(c, "policy_arn")...)
	}
	return out
}

type issue struct {
	sev rules.Severity
	msg string
}

func (r *IAMWildcard) documentFindings(c plan.Change, path []any) []rules.Finding {
	attr := plan.FormatPath(path)
	if c.IsUnknown(path...) {
		return []rules.Finding{rules.New(r.Meta(), c, rules.SeverityInfo,
			attr+" is known only after apply; wildcard grants cannot be checked, review it manually")}
	}
	after, _ := plan.Lookup(c.After, path...)
	afterDoc, ok := after.(string)
	if !ok || afterDoc == "" {
		return nil
	}
	afterIssues, err := analysePolicy(afterDoc)
	if err != nil {
		return []rules.Finding{rules.New(r.Meta(), c, rules.SeverityInfo,
			fmt.Sprintf("%s is not a valid policy document (%v); review it manually", attr, err))}
	}
	var beforeIssues []issue
	if before, ok := plan.Lookup(c.Before, path...); ok {
		if doc, ok := before.(string); ok {
			beforeIssues, _ = analysePolicy(doc)
		}
	}

	var out []rules.Finding
	for _, is := range afterIssues {
		if slices.Contains(beforeIssues, is) {
			continue
		}
		msg := is.msg
		if c.Action == plan.ActionUpdate {
			msg += " (added)"
		}
		out = append(out, rules.New(r.Meta(), c, is.sev, attr+": "+msg))
	}
	return out
}

func (r *IAMWildcard) attachmentFindings(c plan.Change, attr string) []rules.Finding {
	before := stringList(c.Before[attr])
	var out []rules.Finding
	for _, arn := range stringList(c.After[attr]) {
		if slices.Contains(before, arn) {
			continue
		}
		name, ok := strings.CutPrefix(arn, "arn:aws:iam::aws:policy/")
		if !ok {
			continue
		}
		if sev, ok := adminManagedPolicies[name]; ok {
			out = append(out, rules.New(r.Meta(), c, sev, fmt.Sprintf("%s: attaches AWS managed policy %s", attr, name)))
		}
	}
	return out
}

type policyDocument struct {
	Statement json.RawMessage `json:"Statement"`
}

type statement struct {
	Sid       string          `json:"Sid"`
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	NotAction json.RawMessage `json:"NotAction"`
	Resource  json.RawMessage `json:"Resource"`
}

// analysePolicy returns the wildcard issues of a policy document. Issues are
// comparable so before/after documents can be diffed.
func analysePolicy(doc string) ([]issue, error) {
	var pd policyDocument
	if err := json.Unmarshal([]byte(doc), &pd); err != nil {
		return nil, err
	}
	var stmts []statement
	if len(pd.Statement) > 0 && pd.Statement[0] == '{' {
		var s statement
		if err := json.Unmarshal(pd.Statement, &s); err != nil {
			return nil, err
		}
		stmts = []statement{s}
	} else if len(pd.Statement) > 0 {
		if err := json.Unmarshal(pd.Statement, &stmts); err != nil {
			return nil, err
		}
	}

	var out []issue
	add := func(is issue) {
		if !slices.Contains(out, is) {
			out = append(out, is)
		}
	}
	for i, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		where := "statement " + strconv.Itoa(i)
		if s.Sid != "" {
			where = "statement " + strconv.Quote(s.Sid)
		}
		actions := oneOrMany(s.Action)
		resources := oneOrMany(s.Resource)
		anyResource := slices.Contains(resources, "*")

		if len(s.NotAction) > 0 {
			add(issue{rules.SeverityHigh, where + ": Allow with NotAction grants every action except the listed ones"})
		}
		if slices.Contains(actions, "*") {
			if anyResource {
				add(issue{rules.SeverityCritical, where + `: Action "*" on Resource "*" (full administrator access)`})
			} else {
				add(issue{rules.SeverityHigh, where + `: Action "*" grants every action on ` + strings.Join(resources, ", ")})
			}
			continue
		}
		if !anyResource {
			continue
		}
		var writes []string
		for _, a := range actions {
			svc, verb, _ := strings.Cut(a, ":")
			switch {
			case verb == "*":
				sev := rules.SeverityMedium
				if slices.Contains(privilegedServices, strings.ToLower(svc)) {
					sev = rules.SeverityHigh
				}
				add(issue{sev, fmt.Sprintf(`%s: Action %q on Resource "*"`, where, a)})
			case strings.EqualFold(svc, "iam") && matchesAction(verb, "PassRole"):
				add(issue{rules.SeverityHigh, fmt.Sprintf(`%s: %q on Resource "*" lets the principal pass any role to a service (privilege escalation)`, where, a)})
			case !isReadVerb(verb):
				writes = append(writes, a)
			}
		}
		if len(writes) > 0 {
			const maxShown = 5
			shown := writes
			suffix := ""
			if len(shown) > maxShown {
				shown, suffix = shown[:maxShown], fmt.Sprintf(" and %d more", len(writes)-maxShown)
			}
			add(issue{rules.SeverityMedium, fmt.Sprintf(`%s: write actions %s%s on Resource "*"`, where, strings.Join(shown, ", "), suffix)})
		}
	}
	return out, nil
}

// matchesAction reports whether an action verb pattern (possibly with a
// trailing *) covers the given verb.
func matchesAction(pattern, verb string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(strings.ToLower(verb), strings.ToLower(prefix))
	}
	return strings.EqualFold(pattern, verb)
}

func isReadVerb(verb string) bool {
	for _, p := range readVerbPrefixes {
		if len(verb) >= len(p) && strings.EqualFold(verb[:len(p)], p) {
			return true
		}
	}
	return false
}

func oneOrMany(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}
