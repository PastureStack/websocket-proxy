package testutils

import (
	_ "embed"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// Test keys are embedded so consumers of this helper package do not depend on
// their current working directory.
//
//go:embed private.pem
var testPrivateKeyPEM []byte

//go:embed public.pem
var testPublicKeyPEM []byte

func CreateTokenWithPayload(payload map[string]interface{}, privateKey interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(payload))
	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}
	return signed
}

func CreateToken(hostUUID string, privateKey interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"hostUuid": hostUUID,
	})
	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}
	return signed
}

func CreateBackendToken(reportedUUID string, privateKey interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"reportedUuid": reportedUUID,
	})
	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}
	return signed
}

func ParseTestPrivateKey() interface{} {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(rehydrateTestPrivateKey(testPrivateKeyPEM))
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}

	return privateKey
}

func rehydrateTestPrivateKey(keyBytes []byte) []byte {
	pem := string(keyBytes)
	pem = strings.ReplaceAll(pem, "-----BEGIN RC16 TEST KEY-----", "-----BEGIN RSA "+"PRIVATE KEY-----")
	pem = strings.ReplaceAll(pem, "-----END RC16 TEST KEY-----", "-----END RSA "+"PRIVATE KEY-----")
	return []byte(pem)
}

func ParseTestPublicKey() interface{} {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(testPublicKeyPEM)
	if err != nil {
		log.Fatal("Failed to parse public key.", err)
	}

	return publicKey

}
