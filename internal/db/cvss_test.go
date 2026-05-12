package db

import "testing"

func TestBaseScoreFromVector(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		{"v3.1 critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"v3.1 medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, true},
		{"v3.0 high", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5, true},
		{"empty", "", 0, false},
		{"garbage", "not-a-vector", 0, false},
		{"v3.1 truncated", "CVSS:3.1/AV:N/AC:L", 0, false},
		{"unsupported v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BaseScoreFromVector(tc.vector)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("score = %v, want %v", got, tc.want)
			}
		})
	}
}
