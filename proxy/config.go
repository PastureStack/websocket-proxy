package proxy

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	platformRequestTimeout = 10 * time.Second
	maxPublicKeyBytes      = 1 << 20
	maxAPIResponseBytes    = 2 << 20
	maxCertificateZipBytes = 8 << 20
	maxCertificateFileSize = 2 << 20
	minimumRSAKeyBits      = 2048
)

type Config struct {
	PublicKey                interface{}
	ListenAddr               string
	PlatformAddr             string
	ParentPid                int
	ProxyProtoHTTPSPorts     map[int]bool
	TrustedProxyCIDRs        []*net.IPNet
	PlatformAccessKey        string
	PlatformSecretKey        string
	TLSListenAddr            string
	MasterFile               string
	APIInterceptorConfigFile string
	Locale                   string
}

func GetConfig() (*Config, error) {
	c := &Config{
		PlatformAccessKey: preferredEnvironment("PLATFORM_ACCESS_KEY", "CATTLE_ACCESS_KEY"),
		PlatformSecretKey: preferredEnvironment("PLATFORM_SECRET_KEY", "CATTLE_SECRET_KEY"),
	}
	var keyFile string
	var keyContents string
	var proxyProtoHTTPSPorts string
	var trustedProxyCIDRs string
	var apiInterceptorConfigFile string
	var legacyPlatformAddr string

	flag.StringVar(&c.MasterFile, "master-file", "", "Location of the file containing the master address.")
	flag.StringVar(&keyFile, "jwt-public-key-file", "", "Location of the public-key used to validate JWTs.")
	flag.StringVar(&keyContents, "jwt-public-key-contents", "", "An alternative to jwt-public-key-file. The contents of the key.")
	flag.StringVar(&c.ListenAddr, "listen-address", ":8080", "The tcp address to listen on.")
	flag.StringVar(&c.TLSListenAddr, "tls-listen-address", "", "The tcp address to listen on for swarm.")
	flag.StringVar(&c.PlatformAddr, "platform-address", "", "The TCP address to forward control-platform API requests to.")
	flag.StringVar(&legacyPlatformAddr, "cattle-address", "", "Legacy alias for platform-address.")
	localeDefault := os.Getenv("PASTURESTACK_LOCALE")
	if localeDefault == "" {
		localeDefault = "en-US"
	}
	flag.StringVar(&c.Locale, "locale", localeDefault, "Operator message locale: en-US or zh-TW")
	flag.IntVar(&c.ParentPid, "parent-pid", 0, "If provided, this process will exit when the specified parent process stops running.")
	flag.StringVar(&proxyProtoHTTPSPorts, "https-proxy-protocol-ports", "", "If proxy protocol is used, a list of proxy ports that will allow us to recognize that the connection was over https.")
	flag.StringVar(&trustedProxyCIDRs, "trusted-proxy-cidrs", "127.0.0.0/8,::1/128", "Comma-separated source CIDRs allowed to send Proxy Protocol headers.")
	flag.StringVar(&apiInterceptorConfigFile, "api-interceptor-config-file", "", "Location of the config.json that defines the API interceptors.")

	if !flag.Parsed() {
		flag.Parse()
	}
	if err := applyEnvironmentToUnsetFlags(flag.CommandLine, "PROXY_"); err != nil {
		return nil, err
	}
	if c.PlatformAddr == "" {
		c.PlatformAddr = legacyPlatformAddr
	}
	if c.Locale != "en-US" && c.Locale != "zh-TW" {
		return nil, fmt.Errorf("unsupported locale %q; use en-US or zh-TW", c.Locale)
	}

	if keyFile != "" && keyContents != "" {
		return nil, fmt.Errorf("Can't specify both jwt-public-key-file and jwt-public-key-contents")
	}
	var parsedKey interface{}
	var parseErr error
	if keyFile != "" {
		parsedKey, parseErr = ParsePublicKey(keyFile)
	} else if keyContents != "" {
		parsedKey, parseErr = ParsePublicKeyFromMemory(keyContents)
	} else if c.PlatformAddr != "" {
		bytes, err := downloadKey(c.PlatformAddr)
		if err != nil {
			parseErr = err
		}
		parsedKey, parseErr = publicKeyDecode(bytes)
	} else {
		parseErr = fmt.Errorf("Must specify one of jwt-public-key-file and jwt-public-key-contents")
	}
	if parseErr != nil {
		return nil, parseErr
	}

	c.PublicKey = parsedKey

	portMap := make(map[int]bool)
	ports := strings.Split(proxyProtoHTTPSPorts, ",")
	for _, port := range ports {
		if p, err := strconv.Atoi(port); err == nil {
			portMap[p] = true
		}
	}
	c.ProxyProtoHTTPSPorts = portMap
	c.TrustedProxyCIDRs, parseErr = parseTrustedProxyCIDRs(trustedProxyCIDRs)
	if parseErr != nil {
		return nil, parseErr
	}
	c.APIInterceptorConfigFile = apiInterceptorConfigFile

	return c, nil
}

func parseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q", value)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func applyEnvironmentToUnsetFlags(flagSet *flag.FlagSet, prefix string) error {
	alreadySet := make(map[string]bool)
	flagSet.Visit(func(item *flag.Flag) {
		alreadySet[item.Name] = true
	})
	var applyErr error
	flagSet.VisitAll(func(item *flag.Flag) {
		if applyErr != nil || alreadySet[item.Name] {
			return
		}
		key := strings.ToUpper(prefix + strings.NewReplacer(".", "_", "-", "_").Replace(item.Name))
		value := os.Getenv(key)
		if value == "" {
			return
		}
		if err := flagSet.Set(item.Name, value); err != nil {
			applyErr = fmt.Errorf("invalid environment value for %s: %w", key, err)
		}
	})
	return applyErr
}

func preferredEnvironment(preferred, legacy string) string {
	if value := os.Getenv(preferred); value != "" {
		return value
	}
	return os.Getenv(legacy)
}

func (config *Config) GetCerts() (*Certs, error) {
	return downloadCert(config.PlatformAccessKey, config.PlatformSecretKey, config.PlatformAddr)
}

func ParsePublicKey(keyFile string) (interface{}, error) {
	file, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	keyBytes, err := io.ReadAll(io.LimitReader(file, maxPublicKeyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(keyBytes) > maxPublicKeyBytes {
		return nil, fmt.Errorf("JWT public key exceeds %d bytes", maxPublicKeyBytes)
	}

	return publicKeyDecode(keyBytes)
}

func ParsePublicKeyFromMemory(keyFileContents string) (interface{}, error) {
	return publicKeyDecode([]byte(keyFileContents))
}

func publicKeyDecode(keyBytes []byte) (interface{}, error) {
	if len(keyBytes) == 0 || len(keyBytes) > maxPublicKeyBytes {
		return nil, fmt.Errorf("JWT public key must contain between 1 and %d bytes", maxPublicKeyBytes)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("Invalid key content")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok || rsaKey.N == nil {
		return nil, errors.New("JWT public key must be RSA")
	}
	if rsaKey.N.BitLen() < minimumRSAKeyBits {
		return nil, fmt.Errorf("JWT RSA public key must be at least %d bits", minimumRSAKeyBits)
	}

	return rsaKey, nil
}

func downloadKey(addr string) ([]byte, error) {
	baseURL, err := controlPlatformBaseURL(addr)
	if err != nil {
		return nil, err
	}
	keyURL := baseURL.ResolveReference(&url.URL{Path: "/v1/scripts/api.crt"})
	logrus.Info("Downloading JWT verification key from control platform")
	body, _, err := getPlatformResource(baseURL, keyURL, "", "", maxPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to download JWT verification key: %w", err)
	}
	return body, nil
}

func controlPlatformBaseURL(addr string) (*url.URL, error) {
	baseURL, err := url.Parse("http://" + addr)
	if err != nil {
		return nil, fmt.Errorf("invalid control-platform address: %w", err)
	}
	if baseURL.Host == "" || baseURL.User != nil || baseURL.Path != "" ||
		baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid control-platform address")
	}
	return baseURL, nil
}

func resolvePlatformResource(baseURL *url.URL, reference string) (*url.URL, error) {
	referenceURL, err := url.Parse(reference)
	if err != nil {
		return nil, fmt.Errorf("invalid control-platform resource URL: %w", err)
	}
	target := baseURL.ResolveReference(referenceURL)
	if target.User != nil || target.Fragment != "" ||
		(target.Scheme != "http" && target.Scheme != "https") ||
		!strings.EqualFold(target.Host, baseURL.Host) {
		return nil, fmt.Errorf("control-platform resource URL is not same-origin")
	}
	return target, nil
}

func getPlatformResource(baseURL, targetURL *url.URL, accessKey, secretKey string, maxBytes int64) ([]byte, http.Header, error) {
	if _, err := resolvePlatformResource(baseURL, targetURL.String()); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create control-platform request: %w", err)
	}
	if accessKey != "" || secretKey != "" {
		req.SetBasicAuth(accessKey, secretKey)
	}
	req.Header.Set("Accept", "application/json, application/zip, application/x-pem-file")

	client := &http.Client{
		Timeout: platformRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("control-platform request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("control-platform request returned HTTP %d", resp.StatusCode)
	}

	limited := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read control-platform response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("control-platform response exceeds %d bytes", maxBytes)
	}
	return body, resp.Header.Clone(), nil
}

type platformSchemaCollection struct {
	Data []struct {
		ID    string            `json:"id"`
		Links map[string]string `json:"links"`
	} `json:"data"`
}

type platformCredentialCollection struct {
	Data []struct {
		Links map[string]string `json:"links"`
	} `json:"data"`
}

func credentialCollectionURL(baseURL *url.URL, accessKey, secretKey string) (*url.URL, error) {
	schemaURL := baseURL.ResolveReference(&url.URL{Path: "/v1/schemas"})
	body, headers, err := getPlatformResource(baseURL, schemaURL, accessKey, secretKey, maxAPIResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load control-platform schemas: %w", err)
	}
	if advertised := headers.Get("X-API-Schemas"); advertised != "" {
		advertisedURL, err := resolvePlatformResource(baseURL, advertised)
		if err != nil {
			return nil, fmt.Errorf("invalid advertised schema URL: %w", err)
		}
		if advertisedURL.String() != schemaURL.String() {
			body, _, err = getPlatformResource(baseURL, advertisedURL, accessKey, secretKey, maxAPIResponseBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to load advertised control-platform schemas: %w", err)
			}
		}
	}

	var schemas platformSchemaCollection
	if err := json.Unmarshal(body, &schemas); err != nil {
		return nil, fmt.Errorf("invalid control-platform schema response: %w", err)
	}
	for _, schema := range schemas.Data {
		if schema.ID != "credential" {
			continue
		}
		collection, ok := schema.Links["collection"]
		if !ok || collection == "" {
			return nil, fmt.Errorf("credential schema has no collection URL")
		}
		collectionURL, err := resolvePlatformResource(baseURL, collection)
		if err != nil {
			return nil, fmt.Errorf("invalid credential collection URL: %w", err)
		}
		return collectionURL, nil
	}
	return nil, fmt.Errorf("control-platform credential schema is unavailable")
}

func extractCertificateArchive(archive []byte) (*Certs, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("invalid certificate archive: %w", err)
	}
	if len(zipReader.File) > 16 {
		return nil, fmt.Errorf("certificate archive contains too many entries")
	}

	result := &Certs{}
	found := make(map[string]bool, 3)
	for _, file := range zipReader.File {
		if file.Name != "ca.pem" && file.Name != "cert.pem" && file.Name != "key.pem" {
			continue
		}
		if found[file.Name] {
			return nil, fmt.Errorf("certificate archive contains duplicate %s", file.Name)
		}
		if file.UncompressedSize64 > maxCertificateFileSize {
			return nil, fmt.Errorf("certificate archive entry %s is too large", file.Name)
		}

		entry, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("could not open certificate archive entry %s: %w", file.Name, err)
		}
		limited := &io.LimitedReader{R: entry, N: maxCertificateFileSize + 1}
		contents, readErr := io.ReadAll(limited)
		closeErr := entry.Close()
		if readErr != nil {
			return nil, fmt.Errorf("could not read certificate archive entry %s: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("could not close certificate archive entry %s: %w", file.Name, closeErr)
		}
		if len(contents) == 0 || int64(len(contents)) > maxCertificateFileSize {
			return nil, fmt.Errorf("certificate archive entry %s has an invalid size", file.Name)
		}
		found[file.Name] = true
		switch file.Name {
		case "ca.pem":
			result.CA = contents
		case "cert.pem":
			result.Cert = contents
		case "key.pem":
			result.Key = contents
		}
	}

	for _, required := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if !found[required] {
			return nil, fmt.Errorf("certificate archive is missing %s", required)
		}
	}
	return result, nil
}

type Certs struct {
	CA   []byte
	Cert []byte
	Key  []byte
}

func downloadCert(accessKey, secretKey, addr string) (*Certs, error) {
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("control-platform credentials are required")
	}
	baseURL, err := controlPlatformBaseURL(addr)
	if err != nil {
		return nil, err
	}
	collectionURL, err := credentialCollectionURL(baseURL, accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	query := collectionURL.Query()
	query.Set("publicValue", accessKey)
	query.Set("kind", "agentApiKey")
	collectionURL.RawQuery = query.Encode()

	body, _, err := getPlatformResource(baseURL, collectionURL, accessKey, secretKey, maxAPIResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate credential: %w", err)
	}
	var credentials platformCredentialCollection
	if err := json.Unmarshal(body, &credentials); err != nil {
		return nil, fmt.Errorf("invalid credential response: %w", err)
	}
	if len(credentials.Data) == 0 {
		return nil, fmt.Errorf("certificate credential is unavailable")
	}
	certificateReference := credentials.Data[0].Links["certificate"]
	if certificateReference == "" {
		return nil, fmt.Errorf("certificate credential has no certificate URL")
	}
	certificateURL, err := resolvePlatformResource(baseURL, certificateReference)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate URL: %w", err)
	}
	logrus.Info("Downloading TLS certificate archive from control platform")
	archive, _, err := getPlatformResource(baseURL, certificateURL, accessKey, secretKey, maxCertificateZipBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to download TLS certificate archive: %w", err)
	}
	return extractCertificateArchive(archive)
}
