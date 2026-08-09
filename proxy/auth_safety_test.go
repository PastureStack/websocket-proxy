package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestJWTParserRejectsOversizedTokensAndWeakKeys(t *testing.T) {
	if _, err := parseSignedJWT(strings.Repeat("a", maxJWTBytes+1), nil); err == nil {
		t.Fatal("oversized JWT was accepted")
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"hostUuid": "host-1"})
	signed, err := token.SignedString(weakKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSignedJWT(signed, &weakKey.PublicKey); err == nil {
		t.Fatal("JWT signed with a weak RSA key was accepted")
	}
}
