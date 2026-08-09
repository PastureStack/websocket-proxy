package proxy

import (
	"crypto/rsa"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	expectedJWTAlg = "RS256"
	maxJWTBytes    = 16 << 10
	minRSAKeyBits  = 2048
)

func parseSignedJWT(tokenString string, parsedPublicKey interface{}) (*jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("no JWT provided")
	}
	if len(tokenString) > maxJWTBytes {
		return nil, fmt.Errorf("JWT exceeds %d bytes", maxJWTBytes)
	}
	publicKey, ok := parsedPublicKey.(*rsa.PublicKey)
	if !ok || publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("JWT verification requires an RSA public key of at least %d bits", minRSAKeyBits)
	}
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok || method.Alg() != expectedJWTAlg {
			return nil, fmt.Errorf("unexpected JWT signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{expectedJWTAlg}), jwt.WithJSONNumber())
}

func mapClaims(token *jwt.Token) (jwt.MapClaims, bool) {
	if token == nil {
		return nil, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return claims, ok
}

func stringClaim(token *jwt.Token, key string) (string, bool) {
	value, found := claimValue(token, key)
	if !found {
		return "", false
	}
	valueString, ok := value.(string)
	return valueString, ok
}

func boolClaim(token *jwt.Token, key string) (bool, bool) {
	value, found := claimValue(token, key)
	if !found {
		return false, false
	}
	valueBool, ok := value.(bool)
	return valueBool, ok
}

func objectClaim(token *jwt.Token, key string) (map[string]interface{}, bool) {
	value, found := claimValue(token, key)
	if !found {
		return nil, false
	}
	valueMap, ok := value.(map[string]interface{})
	return valueMap, ok
}

func claimValue(token *jwt.Token, key string) (interface{}, bool) {
	claims, ok := mapClaims(token)
	if !ok {
		return nil, false
	}
	value, found := claims[key]
	if !found {
		return nil, false
	}
	return value, true
}

func redactSecretForLog(value string) string {
	if value == "" {
		return ""
	}
	return "[redacted]"
}
