package db

import (
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

// BaseScoreFromVector computes the CVSS base score for a v3.0 or v3.1
// vector. Returns (0, false) when the vector is empty or unparseable;
// callers should clear cvss_score in that case rather than pinning a
// stale value next to a fresh (or removed) vector.
func BaseScoreFromVector(vector string) (float64, bool) {
	if vector == "" {
		return 0, false
	}
	if v, err := gocvss31.ParseVector(vector); err == nil {
		return v.BaseScore(), true
	}
	if v, err := gocvss30.ParseVector(vector); err == nil {
		return v.BaseScore(), true
	}
	return 0, false
}
