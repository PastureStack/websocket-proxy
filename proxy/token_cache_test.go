package proxy

import (
	"fmt"
	"testing"
	"time"
)

func TestTokenCacheExpiresEntries(t *testing.T) {
	now := time.Unix(1_000, 0)
	cache := newTokenCache(30 * time.Second)
	cache.now = func() time.Time { return now }

	cache.set("request", "token")
	if token, ok := cache.get("request"); !ok || token != "token" {
		t.Fatalf("fresh token = %q, %v; want token, true", token, ok)
	}

	now = now.Add(30 * time.Second)
	if token, ok := cache.get("request"); ok || token != "" {
		t.Fatalf("expired token = %q, %v; want empty, false", token, ok)
	}
}

func TestTokenCacheBoundsUniqueKeys(t *testing.T) {
	now := time.Unix(2_000, 0)
	cache := newTokenCache(time.Minute)
	cache.now = func() time.Time { return now }

	for index := 0; index <= maxTokenCacheEntries; index++ {
		cache.set(fmt.Sprintf("key-%d", index), "token")
		now = now.Add(time.Millisecond)
	}

	if got := len(cache.entries); got != maxTokenCacheEntries {
		t.Fatalf("cache size = %d; want %d", got, maxTokenCacheEntries)
	}
	if token, ok := cache.get(fmt.Sprintf("key-%d", maxTokenCacheEntries)); !ok || token != "token" {
		t.Fatalf("newest token = %q, %v; want token, true", token, ok)
	}
}
