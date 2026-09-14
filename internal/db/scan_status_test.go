package db

import (
	"testing"
	"time"
)

var allScanStatuses = []ScanStatus{
	ScanQueued, ScanRunning, ScanPaused, ScanDone, ScanFailed, ScanSkipped, ScanCancelled,
}

func TestStoppedMatchesTerminalPlusPaused(t *testing.T) {
	want := map[ScanStatus]bool{
		ScanQueued:    false,
		ScanRunning:   false,
		ScanPaused:    true,
		ScanDone:      true,
		ScanFailed:    true,
		ScanSkipped:   true,
		ScanCancelled: true,
	}
	for _, s := range allScanStatuses {
		if got := s.Stopped(); got != want[s] {
			t.Errorf("%s.Stopped() = %v, want %v", s, got, want[s])
		}
	}
}

func TestStatusPriorityAgreesWithTheStateModel(t *testing.T) {
	// The sort key must rank live work above stopped work and never split
	// the terminal states, or the scans index would order rows by something
	// other than what their status means.
	order := []ScanStatus{ScanRunning, ScanQueued, ScanPaused, ScanDone}
	for i := 1; i < len(order); i++ {
		before, after := order[i-1], order[i]
		if StatusPriorityFor(before) >= StatusPriorityFor(after) {
			t.Errorf("priority order broken: %s=%d should sort before %s=%d",
				before, StatusPriorityFor(before), after, StatusPriorityFor(after))
		}
	}
	for _, s := range allScanStatuses {
		if s.Terminal() != (StatusPriorityFor(s) == scanPriorityTerminal) {
			t.Errorf("%s: Terminal()=%v but priority=%d (terminal bucket is %d)",
				s, s.Terminal(), StatusPriorityFor(s), scanPriorityTerminal)
		}
	}
}

func TestStampScanStatusDerivesTheColumnsFromTheStatus(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	stale := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, s := range allScanStatuses {
		// Seed both derived columns wrong so the stamp has to move them.
		scan := Scan{Status: s, StatusPriority: -1, FinishedAt: &stale}
		StampScanStatus(&scan, at)
		if scan.StatusPriority != StatusPriorityFor(s) {
			t.Errorf("%s: priority = %d, want %d", s, scan.StatusPriority, StatusPriorityFor(s))
		}
		switch {
		case s.Stopped() && (scan.FinishedAt == nil || !scan.FinishedAt.Equal(at)):
			t.Errorf("%s: FinishedAt = %v, want %v", s, scan.FinishedAt, at)
		case !s.Stopped() && scan.FinishedAt != nil:
			t.Errorf("%s: FinishedAt = %v, want nil", s, scan.FinishedAt)
		}
	}
}

func TestSetScanStatusSetsAndStamps(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	scan := Scan{Status: ScanRunning, StatusPriority: StatusPriorityFor(ScanRunning)}
	SetScanStatus(&scan, ScanDone, at)
	if scan.Status != ScanDone {
		t.Errorf("Status = %s, want %s", scan.Status, ScanDone)
	}
	if scan.StatusPriority != StatusPriorityFor(ScanDone) {
		t.Errorf("StatusPriority = %d, want %d", scan.StatusPriority, StatusPriorityFor(ScanDone))
	}
	if scan.FinishedAt == nil || !scan.FinishedAt.Equal(at) {
		t.Errorf("FinishedAt = %v, want %v", scan.FinishedAt, at)
	}

	// Resuming through the struct form clears the stop timestamp again.
	SetScanStatus(&scan, ScanQueued, at)
	if scan.FinishedAt != nil {
		t.Errorf("after requeue FinishedAt = %v, want nil", scan.FinishedAt)
	}
}

// scanStatusUpdateKeys is the full column set every transition writes; a
// missing key would leave the previous state's value behind on that column.
var scanStatusUpdateKeys = []string{"status", "status_priority", "error", "finished_at", "paused_until"}

func TestScanStatusUpdatesDerivesFinishedAtFromTheStatus(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	until := at.Add(time.Hour)

	for _, s := range allScanStatuses {
		m := ScanStatusUpdates(s, "why", at, nil)
		if len(m) != len(scanStatusUpdateKeys) {
			t.Errorf("%s: %d keys, want %d (%v)", s, len(m), len(scanStatusUpdateKeys), m)
		}
		for _, k := range scanStatusUpdateKeys {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: key %q missing", s, k)
			}
		}
		if m["status"] != s || m["status_priority"] != StatusPriorityFor(s) || m["error"] != "why" {
			t.Errorf("%s: unexpected values %v", s, m)
		}
		finished := m["finished_at"].(*time.Time)
		switch {
		case s.Stopped() && (finished == nil || !finished.Equal(at)):
			t.Errorf("%s: finished_at = %v, want %v", s, finished, at)
		case !s.Stopped() && finished != nil:
			t.Errorf("%s: finished_at = %v, want nil", s, finished)
		}
	}

	m := ScanStatusUpdates(ScanPaused, "paused", at, &until)
	if got := m["paused_until"].(*time.Time); got == nil || !got.Equal(until) {
		t.Errorf("paused_until = %v, want %v", got, until)
	}
}

func TestRequeueScanUpdatesClearsTheStoppedState(t *testing.T) {
	m := RequeueScanUpdates()
	if m["status"] != ScanQueued || m["status_priority"] != StatusPriorityFor(ScanQueued) || m["error"] != "" {
		t.Errorf("unexpected requeue map %v", m)
	}
	if m["finished_at"].(*time.Time) != nil {
		t.Errorf("finished_at = %v, want nil", m["finished_at"])
	}
	if m["paused_until"] != (*time.Time)(nil) {
		t.Errorf("paused_until = %v, want nil", m["paused_until"])
	}
}

func TestSweepRunningMovesTheSortKeyWithTheStatus(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/sweep", Name: "sweep"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	orphaned := Scan{RepositoryID: repo.ID, Kind: "skill", Status: ScanRunning,
		StatusPriority: StatusPriorityFor(ScanRunning)}
	settled := Scan{RepositoryID: repo.ID, Kind: "skill", Status: ScanDone,
		StatusPriority: StatusPriorityFor(ScanDone), FinishedAt: &finished}
	if err := gdb.Create(&orphaned).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&settled).Error; err != nil {
		t.Fatal(err)
	}

	if err := SweepRunning(gdb); err != nil {
		t.Fatal(err)
	}

	var got Scan
	if err := gdb.First(&got, orphaned.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != ScanFailed {
		t.Errorf("swept status = %s, want %s", got.Status, ScanFailed)
	}
	// The regression this pins: the sweep used to flip status but leave the
	// denormalised sort key at running, so orphaned rows sat on top of the
	// scans index for the rest of the server's life.
	if got.StatusPriority != StatusPriorityFor(ScanFailed) {
		t.Errorf("swept priority = %d, want %d", got.StatusPriority, StatusPriorityFor(ScanFailed))
	}
	if got.FinishedAt == nil {
		t.Error("swept scan has no finished_at; it is invisible to every timeline reader")
	}

	var untouched Scan
	if err := gdb.First(&untouched, settled.ID).Error; err != nil {
		t.Fatal(err)
	}
	if untouched.Status != ScanDone || !untouched.FinishedAt.Equal(finished) {
		t.Errorf("done row changed by the sweep: status=%s finished=%v", untouched.Status, untouched.FinishedAt)
	}
}
