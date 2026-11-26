package firewall

import (
	"errors"
	"testing"
)

func TestCollectRulesetsKeepsGoingAfterFailure(t *testing.T) {
	targets := []snapshotTarget{
		{"k", "a", []string{"one"}},
		{"k", "b", []string{"two"}},
	}
	var ran [][]string
	got := collectRulesets(targets, func(args ...string) ([]byte, error) {
		ran = append(ran, args)
		if args[0] == "one" {
			return []byte("\n rules A \n"), nil
		}
		return []byte("boom"), errors.New("exit status 1")
	})
	if len(got) != 2 || len(ran) != 2 {
		t.Fatalf("got %d results, %d runs", len(got), len(ran))
	}
	if got[0].Rules != "rules A" || got[0].Error != "" || got[0].Name != "a" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Error == "" || got[1].Rules != "boom" {
		t.Errorf("failure must be recorded, not dropped: %+v", got[1])
	}
}
