package common

import (
	"regexp"
	"testing"
)

func TestNewRandomUUID(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		value := NewRandomUUID()
		if !pattern.MatchString(value) {
			t.Fatalf("invalid RFC 4122 version 4 UUID: %q", value)
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate UUID: %q", value)
		}
		seen[value] = struct{}{}
	}
}
