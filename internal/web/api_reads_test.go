package web

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestAPIListFindings_filtersBySkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)

	mkScan := func(skillName string) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: skillName}
		s.DB.Create(&sc)
		return sc
	}
	semgrep := mkScan("semgrep")
	deepDive := mkScan("security-deep-dive")

	s.DB.Create(&db.Finding{ScanID: semgrep.ID, RepositoryID: repo.ID, Title: "sg1",
		Severity: "Medium", CWE: "CWE-79", Location: "a.rb:1"})
	s.DB.Create(&db.Finding{ScanID: semgrep.ID, RepositoryID: repo.ID, Title: "sg2",
		Severity: "High", CWE: "CWE-89", Location: "b.rb:1"})
	s.DB.Create(&db.Finding{ScanID: deepDive.ID, RepositoryID: repo.ID, Title: "dd1",
		Severity: "High", CWE: "CWE-22", Location: "c.rb:1"})

	get := func(q string) []map[string]any {
		r := httptest.NewRequest("GET", fmt.Sprintf("/api/repositories/%d/findings%s", repo.ID, q), nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+auth.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", q, w.Code, w.Body)
		}
		var rows []map[string]any
		_ = json.NewDecoder(w.Body).Decode(&rows)
		return rows
	}

	if got := get(""); len(got) != 3 {
		t.Errorf("no filter: %d findings, want 3", len(got))
	}
	sg := get("?skill=semgrep")
	if len(sg) != 2 {
		t.Fatalf("?skill=semgrep: %d findings, want 2", len(sg))
	}
	for _, f := range sg {
		if f["title"] != "sg1" && f["title"] != "sg2" {
			t.Errorf("?skill=semgrep returned %v", f["title"])
		}
	}
	if got := get("?skill=security-deep-dive"); len(got) != 1 || got[0]["title"] != "dd1" {
		t.Errorf("?skill=security-deep-dive: got %v", got)
	}
	if got := get("?skill=nonexistent"); len(got) != 0 {
		t.Errorf("?skill=nonexistent: %d findings, want 0", len(got))
	}
	if got := get("?skill=semgrep&severity=High"); len(got) != 1 || got[0]["title"] != "sg2" {
		t.Errorf("?skill=semgrep&severity=High: got %v", got)
	}
}
