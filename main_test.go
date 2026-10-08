package main

import (
	"regexp"
	"testing"
)

func TestTraditionalChineseOperatorMessage(t *testing.T) {
	if got := operatorMessage("zh-TW", "start"); got != "正在啟動 PastureStack WebSocket 代理服務。" {
		t.Fatalf("unexpected zh-TW message: %q", got)
	}
}

func TestVersionRequested(t *testing.T) {
	if !versionRequested([]string{"--version"}) {
		t.Fatal("expected --version to be recognized")
	}
	if versionRequested([]string{"--listen-address", ":8080"}) {
		t.Fatal("ordinary arguments must not trigger version output")
	}
}

func TestDefaultVersionIsNumeric(t *testing.T) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(VERSION) {
		t.Fatalf("default build version must be numeric, got %q", VERSION)
	}
}
