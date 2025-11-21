package tests

import (
	"github.com/snukone/rocketguard/cmd/rocketguard"
	"os"
	"testing"
)

func TestLoadReceiverMap(t *testing.T) {
	data := []byte("rocketchat:testurl")
	os.WriteFile("test_receivers.yaml", data, 0644)
	defer os.Remove("test_receivers.yaml")

	_, err := rocketguard.LoadReceiverMap("test_receivers.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
