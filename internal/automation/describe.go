package automation

import (
	"fmt"
	"strings"
)

// DescribeCondition renders c as a short English phrase for logs and the
// automation event's rule_text ("SSID is not Home", "SSID is any of
// Home, Office", "connection type is wired", "subnet is 10.0.0.0/24", "no
// other rule matches"). GUIs localise from the rule
// itself; this is the fallback and log form.
func DescribeCondition(c Condition) string {
	is := "is"
	if c.Negate {
		is = "is not"
	}
	switch c.Type {
	case CondSSID:
		set := SSIDSet(c)
		if len(set) > 1 {
			anyOf := "is any of"
			if c.Negate {
				anyOf = "is none of"
			}
			return fmt.Sprintf("SSID %s %s", anyOf, strings.Join(set, ", "))
		}
		return fmt.Sprintf("SSID %s %s", is, strings.Join(set, ""))
	case CondMedium:
		return fmt.Sprintf("connection type %s %s", is, c.Medium)
	case CondSubnet:
		return fmt.Sprintf("subnet %s %s", is, c.Subnet)
	case CondNetwork:
		name := c.GatewayMAC
		if c.Label != "" {
			name = c.Label
		}
		return fmt.Sprintf("network %s %s", is, name)
	case CondNoneMatch:
		return "no other rule matches"
	}
	return c.Type
}

// DescribeRule describes rules[index]'s condition, "" when index is out of
// range (e.g. -1 for a decision no single rule made).
func DescribeRule(rules []Rule, index int) string {
	if index < 0 || index >= len(rules) {
		return ""
	}
	return DescribeCondition(rules[index].When)
}
