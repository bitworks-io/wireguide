package diag

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// localeLangs are the GUI languages; a key missing from any of them renders
// as the raw key there.
var localeLangs = []string{"en", "ko", "ja", "zh"}

func loadLocales(t *testing.T) map[string]map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]map[string]any{}
	for _, l := range localeLangs {
		b, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "i18n", l+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var d map[string]map[string]any
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		out[l] = d
	}
	return out
}

// localeString returns section.key in one language ("" when absent).
func localeString(d map[string]map[string]any, section, key string) string {
	s, _ := d[section][key].(string)
	return s
}

const keysScutil = `DNS configuration

resolver #1
  nameserver[0] : 192.168.50.1

resolver #2
  domain   : ok.example
  nameserver[0] : 10.66.66.1

resolver #3
  domain   : mismatch.example
  nameserver[0] : 192.168.50.53

resolver #4
  domain   : outside.example
  nameserver[0] : 172.16.5.2
`

// emittedVerifyRows drives verifyWith through every branch that produces a
// row, so the key test below sees every check, status, detail and hint key
// the Go code can emit.
func emittedVerifyRows(t *testing.T) []VerifyRow {
	t.Helper()
	ctx := context.Background()
	routes := map[string]string{
		"10.66.66.0/24": "utun4", "10.20.0.0/16": "en0", "192.168.50.0/24": "utun4",
	}
	resolveByName := map[string]*ResolveResult{
		"ok.example":      {Name: "ok.example", Addrs: []string{"10.66.66.9"}, Resolver: "10.66.66.1", MatchDomain: "ok.example", DurationMs: 3},
		"nx.example":      {Name: "nx.example", NXDomain: true, Error: "NXDOMAIN", Resolver: "10.66.66.1", DurationMs: 3},
		"slow.example":    {Name: "slow.example", TimedOut: true, Error: "no answer within 3s", DurationMs: 3000},
		"broken.example":  {Name: "broken.example", Error: "server misbehaving"},
		"outside.example": {Name: "outside.example", Addrs: []string{"10.66.66.8"}, Resolver: "172.16.5.2", MatchDomain: "outside.example", DurationMs: 4},
	}
	newDeps := func(goos string, scutilErr bool) verifyDeps {
		return verifyDeps{
			goos: goos,
			run: func(_ context.Context, name string, args ...string) ([]byte, error) {
				switch name {
				case "scutil":
					if scutilErr {
						return nil, errors.New("exit 1")
					}
					return []byte(keysScutil), nil
				case "route":
					if iface, ok := routes[args[len(args)-1]]; ok {
						return []byte("interface: " + iface + "\n"), nil
					}
					return nil, errors.New("not in table")
				}
				return nil, errors.New("unexpected " + name)
			},
			localAddrs: func() []*net.IPNet { return []*net.IPNet{hostAddr(t, "192.168.50.10/24")} },
			resolve:    func(_ context.Context, name string) *ResolveResult { return resolveByName[name] },
			ping: func(_ context.Context, host string) (float64, error) {
				if host == "down" {
					return 0, errors.New("no reply")
				}
				return 1.5, nil
			},
		}
	}
	split := []string{"10.66.66.1", "172.16.5.2", "~ok.example", "~mismatch.example", "~outside.example", "~missing.example"}
	base := VerifyInput{Connected: true, Interface: "utun4", LastHandshake: "3s", DNS: split,
		AllowedIPs: []string{"10.66.66.0/24", "10.20.0.0/16", "192.168.50.0/24", "10.99.0.0/24",
			"10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24", "10.5.0.0/24", "10.6.0.0/24"}}

	var rows []VerifyRow
	add := func(d verifyDeps, in VerifyInput) { rows = append(rows, verifyWith(ctx, d, in)...) }

	add(newDeps("darwin", false), VerifyInput{}) // not connected
	for _, ping := range []string{"10.66.66.1", "down"} {
		for name := range resolveByName {
			in := base
			in.PingHost, in.ResolveName = ping, name
			add(newDeps("darwin", false), in)
		}
	}
	for _, hs := range []string{"", "10m 0s"} {
		in := base
		in.LastHandshake = hs
		add(newDeps("darwin", true), in) // also: scutil failure
	}
	add(newDeps("windows", false), base) // route + resolver unsupported
	for _, tbl := range []string{"off", "100"} {
		in := base
		in.Table = tbl
		add(newDeps("linux", false), in)
	}
	return rows
}

var placeholderRe = regexp.MustCompile(`\{(\w+)\}`)

// TestVerifyKeysTranslated asserts that every verify key the Go code can emit
// exists, non-empty, in all four locales, and that the localised details only
// use placeholders the row actually carries.
func TestVerifyKeysTranslated(t *testing.T) {
	loc := loadLocales(t)
	rows := emittedVerifyRows(t)

	keys := map[string]bool{}
	detailParams := map[string]map[string]bool{}
	nDetail, nHint := map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		keys["check_"+r.Check] = true
		keys["status_"+r.Status] = true
		if r.HintKey != "" {
			keys["hint_"+r.HintKey] = true
			nHint[r.HintKey] = true
		}
		if r.DetailKey != "" {
			k := "detail_" + r.DetailKey
			keys[k] = true
			nDetail[r.DetailKey] = true
			if detailParams[k] == nil {
				detailParams[k] = map[string]bool{}
			}
			for p := range r.DetailParams {
				detailParams[k][p] = true
			}
		}
	}
	// Floors: a fake that silently skips a branch must fail here.
	for _, want := range []string{
		"check_handshake", "check_route", "check_resolver", "check_ping", "check_resolve",
		"status_green", "status_amber", "status_red",
	} {
		if !keys[want] {
			t.Errorf("scenario set never emitted %s", want)
		}
	}
	if len(nDetail) < 23 || len(nHint) < 15 {
		t.Errorf("only %d detail and %d hint keys emitted: %v %v", len(nDetail), len(nHint), nDetail, nHint)
	}

	for _, l := range localeLangs {
		for k := range keys {
			if localeString(loc[l], "verify", k) == "" {
				t.Errorf("%s: verify.%s missing", l, k)
			}
		}
		for k, params := range detailParams {
			for _, m := range placeholderRe.FindAllStringSubmatch(localeString(loc[l], "verify", k), -1) {
				if m[1] != "via" && !params[m[1]] {
					t.Errorf("%s: verify.%s uses {%s}, which the row never carries", l, k, m[1])
				}
			}
		}
		// {via} is rendered from these.
		for _, k := range []string{"dns_try_via", "dns_try_via_domain"} {
			if localeString(loc[l], "tools", k) == "" {
				t.Errorf("%s: tools.%s missing", l, k)
			}
		}
	}
}

// TestDNSChipKeysTranslated asserts that each displayed DNS mode has a chip
// label and hint in all four locales.
func TestDNSChipKeysTranslated(t *testing.T) {
	loc := loadLocales(t)
	for _, mode := range []string{DNSModeGlobal, DNSModeSplit, DNSModeSearch} {
		for _, l := range localeLangs {
			for _, k := range []string{"dns_chip_" + mode, "dns_chip_" + mode + "_hint"} {
				if localeString(loc[l], "tunnel", k) == "" {
					t.Errorf("%s: tunnel.%s missing", l, k)
				}
			}
		}
	}
}
