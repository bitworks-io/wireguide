package wifi

import (
	"fmt"
	"strings"
)

// DescribeCondition renders c as a short English phrase for logs and the
// automation event's rule_text ("SSID is not Home", "subnet is
// 10.0.0.0/24", "no other rule matches"). GUIs localise from the rule
// itself; this is the fallback and log form.
func DescribeCondition(c Condition) string {
	is := "is"
	if c.Negate {
		is = "is not"
	}
	switch c.Type {
	case CondSSID:
		if len(c.SSIDs) == 0 {
			return fmt.Sprintf("SSID %s %s", is, c.SSID)
		}
		set := ssidSet(c)
		if len(set) > 1 {
			in := "is one of"
			if c.Negate {
				in = "is none of"
			}
			return fmt.Sprintf("SSID %s %s", in, strings.Join(set, ", "))
		}
		if len(set) == 1 {
			return fmt.Sprintf("SSID %s %s", is, set[0])
		}
		return fmt.Sprintf("SSID %s %s", is, c.SSID)
	case CondMedium:
		return fmt.Sprintf("connection %s %s", is, MediumLabel(c.Medium))
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
// range.
func DescribeRule(rules []Rule, index int) string {
	if index < 0 || index >= len(rules) {
		return ""
	}
	return DescribeCondition(rules[index].When)
}

// MediumLabel is the English display name of a medium value.
func MediumLabel(m string) string {
	switch normMedium(m) {
	case MediumWiFi:
		return "Wi-Fi"
	case MediumWired:
		return "wired"
	case MediumTethered:
		return "tethered"
	}
	return m
}
