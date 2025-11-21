package tests

import (
	"context"
	"github.com/snukone/rocketguard/cmd/rocketguard"
	"testing"
)

func TestSetIfNotExistsMemory(t *testing.T) {
	ctx := context.Background()
	rocketguard.UseRedis = false
	rg := rocketguard.InitInMemoryCacheForTests(1) // 1s ttl

	ok, err := rocketguard.SetIfNotExists(ctx, "key1", 1)
	if err != nil || !ok {
		t.Fatalf("expected first insert ok, err=%v", err)
	}

	ok, err = rocketguard.SetIfNotExists(ctx, "key1", 1)
	if err != nil || ok {
		t.Fatalf("expected second insert suppressed, err=%v", err)
	}

	_ = rg
}
