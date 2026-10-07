package diag

import "testing"

func TestDNSModeOf(t *testing.T) {
	cases := []struct {
		in      []string
		mode    string
		status  string
		tooltip string
	}{
		{[]string{"1.1.1.1"}, DNSModeGlobal, "global", " (replaces DNS)"},
		{[]string{"192.168.1.1", "~intranet.example", "~corp.lan"}, DNSModeSplit, "split(intranet.example,corp.lan)", " (split DNS)"},
		{nil, DNSModeNone, "none", ""},
		{[]string{"example.com"}, DNSModeSearch, "search", " (search domains)"},
	}
	for _, c := range cases {
		m := DNSModeOf(c.in)
		if m.Mode != c.mode || m.StatusString() != c.status || m.TooltipSuffix() != c.tooltip {
			t.Errorf("%v -> %+v %q %q", c.in, m, m.StatusString(), m.TooltipSuffix())
		}
	}
}

func TestEvaluateSplitDomains(t *testing.T) {
	rows := evaluateSplitDomains(parseScutilDNS(scutilSample), parseEntries([]string{"192.168.1.1", "~intranet.example", "~absent.lan"}))
	if len(rows) != 2 || !rows[0].Registered || rows[0].Resolver != "192.168.1.1" || rows[1].Registered {
		t.Fatalf("%+v", rows)
	}
}
