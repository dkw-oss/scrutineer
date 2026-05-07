package worker

import "testing"

func TestToFindings_carriesReachabilityAndQualityTier(t *testing.T) {
	raw := []byte(`{
	  "findings": [{
	    "id": "F1", "sinks": ["S1"], "title": "heap overflow in parse",
	    "severity": "High", "cwe": "CWE-787", "location": "src/parse.c:42",
	    "reachability": "harness_only", "quality_tier": "high",
	    "trace": "t", "boundary": "b", "validation": "v", "rating": "r"
	  }]
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.toFindings(1, 1, "abc", "")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Reachability != "harness_only" {
		t.Errorf("Reachability = %q, want harness_only", got[0].Reachability)
	}
	if got[0].QualityTier != "high" {
		t.Errorf("QualityTier = %q, want high", got[0].QualityTier)
	}
}
