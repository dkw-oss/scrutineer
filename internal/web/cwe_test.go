package web

import (
	"slices"
	"testing"
)

func TestLookupCWE(t *testing.T) {
	id, c, ok := LookupCWE("79")
	if !ok || id != "CWE-79" || c.Name == "" {
		t.Fatalf("CWE-79: ok=%v id=%q name=%q", ok, id, c.Name)
	}
	if c.Category != "Injection" {
		t.Errorf("CWE-79 category: got %q want %q", c.Category, "Injection")
	}
	if _, c2, _ := LookupCWE("cwe-79"); c2.Name != c.Name {
		t.Error("case-insensitive lookup failed")
	}
	if _, _, ok := LookupCWE("CWE-999999"); ok {
		t.Error("unknown id should miss")
	}
	if _, _, ok := LookupCWE(""); ok {
		t.Error("empty id should miss")
	}
}

func TestCWECategories(t *testing.T) {
	cats := CWECategories()
	if len(cats) != 22 {
		t.Fatalf("want 22 View-1400 categories, got %d", len(cats))
	}
	if !slices.IsSorted(cats) {
		t.Error("categories should be sorted alphabetically")
	}
	for _, want := range []string{"Injection", "Memory Safety", "Access Control"} {
		if !slices.Contains(cats, want) {
			t.Errorf("missing category %q", want)
		}
	}
}

func TestCWEsInCategory(t *testing.T) {
	ids := CWEsInCategory("Injection")
	if len(ids) == 0 {
		t.Fatal("Injection should have members")
	}
	if !slices.Contains(ids, "CWE-79") {
		t.Errorf("Injection should include CWE-79, got %v", ids[:min(5, len(ids))])
	}
	if got := CWEsInCategory("Not A Real Category"); got != nil {
		t.Errorf("unknown category should return nil, got %v", got)
	}
}
