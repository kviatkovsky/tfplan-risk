package aws

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// DefaultCriticalPorts are remote-administration and database ports that must
// never be reachable from the whole internet.
var DefaultCriticalPorts = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	1433:  "SQL Server",
	1521:  "Oracle",
	2049:  "NFS",
	2379:  "etcd",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5439:  "Redshift",
	5601:  "Kibana",
	5984:  "CouchDB",
	6379:  "Redis",
	9092:  "Kafka",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

var openCIDRs = map[string]bool{"0.0.0.0/0": true, "::/0": true}

// SGOpenIngress flags security group ingress opened to 0.0.0.0/0 or ::/0.
type SGOpenIngress struct {
	allowPorts    []int
	criticalPorts map[int]string
}

// NewSGOpenIngress returns the rule with 80 and 443 allowed.
func NewSGOpenIngress() *SGOpenIngress {
	return &SGOpenIngress{allowPorts: []int{80, 443}, criticalPorts: DefaultCriticalPorts}
}

// Meta implements rules.Rule.
func (r *SGOpenIngress) Meta() rules.Meta {
	return rules.Meta{
		ID:       "TPR-SEC-001",
		Title:    "Security group ingress open to the internet",
		Category: rules.CategorySecurity,
		Severity: rules.SeverityCritical,
		Description: "The plan adds an ingress rule that accepts traffic from 0.0.0.0/0 or ::/0. " +
			"Critical when the port range includes a database or remote-administration port (or all " +
			"ports), high otherwise. Ports in allow_ports (default 80, 443) are not reported. " +
			"Only rules that are new in this plan are reported; ICMP is ignored.",
		Checks: []string{
			"aws_security_group: ingress[*].cidr_blocks, ipv6_cidr_blocks, from_port, to_port, protocol",
			"aws_security_group_rule (type = \"ingress\"): cidr_blocks, ipv6_cidr_blocks, from_port, to_port, protocol",
			"aws_vpc_security_group_ingress_rule: cidr_ipv4, cidr_ipv6, from_port, to_port, ip_protocol",
		},
		Example: `resource "aws_vpc_security_group_ingress_rule" "db" {
  security_group_id = aws_security_group.db.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
}`,
		Suggestion: "Restrict the source to known CIDRs or a security group / prefix list. Reach databases " +
			"and hosts through a VPN, bastion or SSM Session Manager instead of public ingress.",
	}
}

// Configure implements rules.Configurable.
func (r *SGOpenIngress) Configure(decode func(any) error) error {
	var opts struct {
		AllowPorts    *[]int `yaml:"allow_ports"`
		CriticalPorts *[]int `yaml:"critical_ports"`
	}
	if err := decode(&opts); err != nil {
		return err
	}
	if opts.AllowPorts != nil {
		r.allowPorts = *opts.AllowPorts
	}
	if opts.CriticalPorts != nil {
		r.criticalPorts = make(map[int]string, len(*opts.CriticalPorts))
		for _, p := range *opts.CriticalPorts {
			if p < 0 || p > 65535 {
				return fmt.Errorf("critical_ports: %d is not a valid port", p)
			}
			r.criticalPorts[p] = DefaultCriticalPorts[p]
		}
	}
	for _, p := range r.allowPorts {
		if p < 0 || p > 65535 {
			return fmt.Errorf("allow_ports: %d is not a valid port", p)
		}
	}
	return nil
}

type exposure struct {
	protocol string // "tcp", "udp", "all", or the raw protocol number
	from, to int
	cidr     string
}

// Evaluate implements rules.Rule.
func (r *SGOpenIngress) Evaluate(c plan.Change) []rules.Finding {
	if c.Action != plan.ActionCreate && c.Action != plan.ActionUpdate && c.Action != plan.ActionReplace {
		return nil
	}
	before := exposures(c.Type, c.Before)
	var out []rules.Finding
	for _, e := range exposures(c.Type, c.After) {
		if slices.Contains(before, e) || r.allowed(e) {
			continue
		}
		sev, what := r.classify(e)
		msg := fmt.Sprintf("ingress from %s on %s", e.cidr, what)
		out = append(out, rules.New(r.Meta(), c, sev, msg))
	}
	return out
}

func (r *SGOpenIngress) allowed(e exposure) bool {
	if e.protocol == "all" || e.to-e.from >= len(r.allowPorts) {
		return false
	}
	for p := e.from; p <= e.to; p++ {
		if !slices.Contains(r.allowPorts, p) {
			return false
		}
	}
	return true
}

func (r *SGOpenIngress) classify(e exposure) (rules.Severity, string) {
	if e.protocol == "all" || (e.from <= 0 && e.to >= 65535) {
		return rules.SeverityCritical, "all ports (" + e.protocol + ")"
	}
	ports := strconv.Itoa(e.from)
	label := "port"
	if e.to != e.from {
		ports += "-" + strconv.Itoa(e.to)
		label = "ports"
	}
	what := fmt.Sprintf("%s %s/%s", label, ports, e.protocol)
	// Report the lowest critical port in range so the message is stable.
	crit := -1
	for p := range r.criticalPorts {
		if p >= e.from && p <= e.to && (crit == -1 || p < crit) {
			crit = p
		}
	}
	if crit >= 0 {
		if name := r.criticalPorts[crit]; name != "" {
			if e.to != e.from {
				return rules.SeverityCritical, fmt.Sprintf("%s (includes %d %s)", what, crit, name)
			}
			return rules.SeverityCritical, fmt.Sprintf("%s (%s)", what, name)
		}
		return rules.SeverityCritical, what
	}
	return rules.SeverityHigh, what
}

// exposures extracts internet-facing ingress entries from a resource value.
func exposures(typ string, obj map[string]any) []exposure {
	if obj == nil {
		return nil
	}
	switch typ {
	case "aws_security_group":
		list, _ := obj["ingress"].([]any)
		var out []exposure
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, fromRule(m, "protocol", "cidr_blocks", "ipv6_cidr_blocks")...)
			}
		}
		return out
	case "aws_security_group_rule":
		if t, _ := obj["type"].(string); t != "ingress" {
			return nil
		}
		return fromRule(obj, "protocol", "cidr_blocks", "ipv6_cidr_blocks")
	case "aws_vpc_security_group_ingress_rule":
		return fromRule(obj, "ip_protocol", "cidr_ipv4", "cidr_ipv6")
	}
	return nil
}

func fromRule(m map[string]any, protoKey string, cidrKeys ...string) []exposure {
	proto, ok := normaliseProtocol(m[protoKey])
	if !ok {
		return nil
	}
	from, to := toInt(m["from_port"]), toInt(m["to_port"])
	if proto == "all" {
		from, to = 0, 65535
	}
	var out []exposure
	for _, key := range cidrKeys {
		for _, cidr := range stringList(m[key]) {
			if openCIDRs[cidr] {
				out = append(out, exposure{protocol: proto, from: from, to: to, cidr: cidr})
			}
		}
	}
	return out
}

// normaliseProtocol maps provider protocol values to a canonical name. The
// second result is false for ICMP, where "ports" are type/code.
func normaliseProtocol(v any) (string, bool) {
	s, _ := v.(string)
	switch s {
	case "-1", "all":
		return "all", true
	case "tcp", "6":
		return "tcp", true
	case "udp", "17":
		return "udp", true
	case "icmp", "1", "icmpv6", "58":
		return "", false
	case "":
		return "", false
	}
	return s, true
}

func toInt(v any) int {
	f, _ := v.(float64)
	return int(f)
}

// stringList accepts a string or a list of strings.
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
