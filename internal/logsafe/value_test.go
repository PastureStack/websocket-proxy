package logsafe

import "testing"

func TestValueRemovesLineBreaks(t *testing.T) {
	if got, want := Value("first\r\nsecond\nthird"), "first second third"; got != want {
		t.Fatalf("Value() = %q, want %q", got, want)
	}
}
