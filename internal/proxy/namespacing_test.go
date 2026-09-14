package proxy

import "testing"

func TestMCPNamespacingHasNoDelimiterCollision(t *testing.T) {
	pairs := [][2]string{{"a", "b__c"}, {"a__b", "c"}, {"a_", "b"}, {"a", "_b"}, {"a_u", "b"}, {"a", "u_b"}, {"plain", "tool"}, {"plain", "list_accounts"}, {"a.u", "b"}, {"a", ".ub"}, {"a", "_.u"}}
	seen := map[string]bool{}
	for _, pair := range pairs {
		name := publicMCPName(pair[0], pair[1])
		if seen[name] {
			t.Fatalf("duplicate namespace %s", name)
		}
		seen[name] = true
		if originalMCPName(pair[0], name) != pair[1] {
			t.Fatalf("not reversible: %v", pair)
		}
	}
	if publicMCPName("plain", "tool") != "plain__tool" || publicMCPName("atlas", "list_accounts") != "atlas__list_accounts" {
		t.Fatal("ordinary names changed")
	}
}
