package testutils

import (
	"io/ioutil"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

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
	keyBytes, err := ioutil.ReadFile("../testutils/private.pem")
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(rehydrateTestPrivateKey(keyBytes))
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
	keyBytes, err := ioutil.ReadFile("../testutils/public.pem")
	if err != nil {
		log.Fatal("Failed to parse public key.", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatal("Failed to parse public key.", err)
	}

	return publicKey

}
