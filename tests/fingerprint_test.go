package tests

import (
	"github.com/snukone/rocketguard/cmd/rocketguard"
	"testing"
)

func TestFingerprintUniqueness(t *testing.T) {
	a1 := &rocketguard.Alert{Labels: map[string]string{"alertname": "A", "job": "j1", "instance": "i1", "severity": "critical"}}
	a2 := &rocketguard.Alert{Labels: map[string]string{"alertname": "A", "job": "j1", "instance": "i1", "severity": "critical"}}

	f1 := rocketguard.Fingerprint(a1)
	f2 := rocketguard.Fingerprint(a2)

	if f1 != f2 {
		t.Fatalf("fingerprints must match, got %s vs %s", f1, f2)
	}
}
