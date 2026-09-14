package db

import "time"

// Scan state lives in three columns that must move together: status itself,
// status_priority (the denormalised sort key the scans index orders on), and
// finished_at (when the run stopped). Nothing in the schema ties them
// together, so every transition goes through the helpers in this file; the
// AST tests in scan_status_invariant_test.go refuse hand-written updates
// anywhere else.
//
// finished_at tracks *stopped*, not *terminal*: pausing a run stamps it and
// resuming clears it, so the row always answers "when did this stop" whether
// or not the stop is final. That split is the two predicates below — Stopped
// for "carries a finished_at", Terminal for "no worker will pick this up
// again".

// Stopped reports whether a scan in this state has stopped running — for
// good (Terminal) or until someone resumes it (paused). Stopped states are
// exactly the ones that carry a finished_at timestamp.
func (s ScanStatus) Stopped() bool {
	return s.Terminal() || s == ScanPaused
}

// StampScanStatus makes a row's derived columns agree with the status
// already set on it: status_priority always follows the status, and
// finished_at is stamped with at on a stopped row and cleared on a live one.
// at is ignored for a state that has not stopped; worker callers pass their
// injectable clock so tests keep governing time.
func StampScanStatus(scan *Scan, at time.Time) {
	scan.StatusPriority = StatusPriorityFor(scan.Status)
	if scan.Status.Stopped() {
		scan.FinishedAt = &at
	} else {
		scan.FinishedAt = nil
	}
}

// SetScanStatus moves a row to status and stamps the derived columns in one
// step.
func SetScanStatus(scan *Scan, status ScanStatus, at time.Time) {
	scan.Status = status
	StampScanStatus(scan, at)
}

// ScanStatusUpdates is the Updates-map form of SetScanStatus, for bulk or
// conditional writes. The map always carries all five state columns so a
// transition clears whatever the previous state left behind. finished_at is
// derived from the status — stopped states stamp it with at, live ones clear
// it — rather than trusted from the caller, so no caller can write a stopped
// row without a timestamp or a live row with one.
func ScanStatusUpdates(status ScanStatus, msg string, at time.Time, pausedUntil *time.Time) map[string]any {
	var finishedAt *time.Time
	if status.Stopped() {
		finishedAt = &at
	}
	return map[string]any{
		"status":          status,
		"status_priority": StatusPriorityFor(status),
		"error":           msg,
		"finished_at":     finishedAt,
		"paused_until":    pausedUntil,
	}
}

// RequeueScanUpdates returns the Updates map that puts a row back on the
// queue: a queued scan has not stopped, carries no error and no pause
// deadline. Time is irrelevant for a live state, so there is no at.
func RequeueScanUpdates() map[string]any {
	return ScanStatusUpdates(ScanQueued, "", time.Time{}, nil)
}
