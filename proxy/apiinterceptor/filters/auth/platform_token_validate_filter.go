package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/filters"
	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/model"
)

const (
	interceptorType              = "authTokenValidator"
	maxPlatformAuthResponseBytes = 2 << 20
	maxPlatformCredentialBytes   = 16 << 10
	platformAuthRequestTimeout   = 10 * time.Second
)

var (
	errPlatformUnauthorized = errors.New("control-platform authentication failed")
	errPlatformForbidden    = errors.New("control-platform access forbidden")
)

// AuthorizeData is for the JSON output
type AuthorizeData struct {
	Message string `json:"message,omitempty"`
}

// MessageData is for the JSON output
type MessageData struct {
	Data []interface{} `json:"data,omitempty"`
}

type TokenValidationFilter struct {
	platformURL string
}

func (*TokenValidationFilter) GetType() string {
	return interceptorType
}

func NewFilter() (filters.APIFilter, error) {
	tokenFilter := &TokenValidationFilter{}

	var addr string
	if os.Getenv("PROXY_PLATFORM_ADDRESS") != "" {
		addr = os.Getenv("PROXY_PLATFORM_ADDRESS")
	} else if os.Getenv("PROXY_CATTLE_ADDRESS") != "" {
		addr = os.Getenv("PROXY_CATTLE_ADDRESS")
	} else {
		log.Infof("PROXY_PLATFORM_ADDRESS is not set, defaulting to localhost:8081")
		addr = "localhost:8081"
	}

	platformURL, err := validatedPlatformURL(addr)
	if err != nil {
		return nil, err
	}
	tokenFilter.platformURL = platformURL

	log.Infof("Configured %s API filter", tokenFilter.GetType())
	return tokenFilter, nil
}

func (f *TokenValidationFilter) ProcessFilter(filter model.FilterData, input model.APIRequestData) (model.APIRequestData, error) {
	output := model.APIRequestData{}

	envid := input.EnvID

	log.Debugf("Request => api=%s method=%s env=%s headers=%v bodyKeys=%v", input.APIPath, input.APIMethod, envid, headerKeys(input.Headers), bodyKeys(input.Body))

	requestHeaders := http.Header(input.Headers)
	authHeader := requestHeaders.Values("Authorization")
	tokenValue, err := exactTokenCookie(requestHeaders)
	if err != nil {
		output.Status = http.StatusBadRequest
		return output, err
	}
	if tokenValue == "" && len(authHeader) == 0 {
		output.Status = http.StatusOK
		log.Debug("No Cookie or Auth headers found in request")
		return output, nil
	}
	for _, value := range authHeader {
		if len(value) > maxPlatformCredentialBytes {
			output.Status = http.StatusBadRequest
			return output, fmt.Errorf("authorization credential exceeds %d bytes", maxPlatformCredentialBytes)
		}
	}

	//check if the token value is empty or not
	if tokenValue != "" || len(authHeader) >= 1 {
		log.Debugf("auth token present via cookie=%v authorizationHeader=%v env=%s", tokenValue != "", len(authHeader) >= 1, envid)

		projectID, accountID, kind, name := "", "", "", ""
		var err error
		if envid != "" {
			projectID, accountID, kind, name, err = getAccountAndProject(f.platformURL, envid, tokenValue, authHeader)
			if err != nil {
				output.Status = platformAuthErrorStatus(err)
				return output, fmt.Errorf("error getting the accountid and projectid: %v", err)
			}
			if accountID == "" || projectID == "" {
				output.Status = http.StatusForbidden
				return output, fmt.Errorf("token or Auth keys forbidden to access the projectid")
			}

		} else {
			accountID, kind, name, err = getAccountID(f.platformURL, tokenValue, authHeader)
			if err != nil {
				output.Status = platformAuthErrorStatus(err)
				return output, fmt.Errorf("error getting the accountid : %v", err)
			}
			if accountID == "" {
				output.Status = http.StatusForbidden
				return output, fmt.Errorf("token or Auth keys forbidden to access the account")
			}
		}

		//construct the responseBody
		var headerBody = make(map[string][]string)

		requestHeader := input.Headers
		for k, v := range requestHeader {
			headerBody[k] = append([]string(nil), v...)
		}

		headerBody["X-API-Account-Id"] = []string{accountID}
		headerBody["X-API-Account-Kind"] = []string{kind}
		if projectID != "" {
			headerBody["X-API-Project-Id"] = []string{projectID}
		}
		if name != "" {
			headerBody["X-API-Account-Name"] = []string{name}
		}

		output.Headers = headerBody
		output.Status = http.StatusOK

		log.Debugf("Response <= status=%d headers=%v", output.Status, headerKeys(output.Headers))
	}

	return output, nil
}

func validatedPlatformURL(addr string) (string, error) {
	parsed, err := url.Parse("http://" + addr)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", fmt.Errorf("invalid control-platform address")
	}
	return parsed.String(), nil
}

func exactTokenCookie(headers http.Header) (string, error) {
	req := &http.Request{Header: headers}
	cookie, err := req.Cookie("token")
	if errors.Is(err, http.ErrNoCookie) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("invalid authentication cookie")
	}
	if len(cookie.Value) > maxPlatformCredentialBytes {
		return "", fmt.Errorf("authentication cookie exceeds %d bytes", maxPlatformCredentialBytes)
	}
	return cookie.Value, nil
}

func platformAuthErrorStatus(err error) int {
	switch {
	case errors.Is(err, errPlatformUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, errPlatformForbidden):
		return http.StatusForbidden
	default:
		return http.StatusBadGateway
	}
}

func headerKeys(headers map[string][]string) []string {
	keys := []string{}
	for key := range headers {
		keys = append(keys, key)
	}
	return keys
}

func bodyKeys(body map[string]interface{}) []string {
	keys := []string{}
	for key := range body {
		keys = append(keys, key)
	}
	return keys
}

// Get the project ID and account ID from the control-platform API.
func getAccountAndProject(host string, envid string, token string, authHeaders []string) (string, string, string, string, error) {
	requestURL := host + "/v2-beta/projects/" + url.PathEscape(envid) + "/accounts"
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return "", "", "", "", fmt.Errorf("cannot connect to the control-platform server; check the platform server URL")
	}
	if token != "" {
		cookie := http.Cookie{Name: "token", Value: token}
		req.AddCookie(&cookie)
	} else {
		req.Header["Authorization"] = authHeaders
	}

	bodyText, headers, status, err := performPlatformAuthRequest(req)
	if err != nil {
		return "", "", "", "", fmt.Errorf("cannot connect to the control-platform server; check the platform server URL")
	}
	if status == http.StatusUnauthorized {
		return "", "", "", "", errPlatformUnauthorized
	}
	if status == http.StatusForbidden {
		return "", "", "", "", errPlatformForbidden
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return "", "", "", "", fmt.Errorf("control-platform account request returned HTTP %d", status)
	}

	err = checkIfAuthorized(bodyText)

	if err != nil {
		return "", "", "", "", err
	}

	projectid := headers.Get("X-Api-Account-Id")
	userid := headers.Get("X-Api-User-Id")
	kind := headers.Get("X-Api-Account-Kind")
	name := headers.Get("X-Api-Account-Name")
	if projectid == "" || userid == "" {
		err := errors.New("token is forbidden to access the projectid")
		return "Forbidden", "Forbidden", "Forbidden", "Forbidden", err

	}
	return projectid, userid, kind, name, nil
}

// Get the account ID from the control-platform API.
func getAccountID(host string, token string, authHeaders []string) (string, string, string, error) {
	requestURL := host + "/v2-beta/accounts"
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("can not get the account api [%v]", err)
	}

	if token != "" {
		cookie := http.Cookie{Name: "token", Value: token}
		req.AddCookie(&cookie)
	} else {
		req.Header["Authorization"] = authHeaders
	}

	bodyText, _, status, err := performPlatformAuthRequest(req)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot connect to the control-platform server")
	}
	if status == http.StatusUnauthorized {
		return "", "", "", errPlatformUnauthorized
	}
	if status == http.StatusForbidden {
		return "", "", "", errPlatformForbidden
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return "", "", "", fmt.Errorf("control-platform account request returned HTTP %d", status)
	}
	err = checkIfAuthorized(bodyText)

	if err != nil {
		return "", "", "", err
	}

	messageData := MessageData{}
	err = json.Unmarshal(bodyText, &messageData)
	if err != nil {
		err := errors.New("can not extract accounts JSON")
		return "", "", "", err
	}
	result := ""
	accKind := ""
	accName := ""
	//get id from the data
	for i := 0; i < len(messageData.Data); i++ {

		idData, suc := messageData.Data[i].(map[string]interface{})
		if suc {
			if idData["id"] == "" || idData["id"] == nil {
				return "", "", "", fmt.Errorf("can not extract user id")
			}
			id, suc := idData["id"].(string)
			if idData["kind"] == "" || idData["kind"] == nil {
				return "", "", "", fmt.Errorf("can not extract user kind")
			}
			kind, namesuc := idData["kind"].(string)
			name, _ := idData["name"].(string)
			if suc && namesuc {
				//if the token belongs to admin, only return the admin token
				if kind == "admin" {
					return id, kind, name, nil
				}
			} else {
				err := errors.New("can not extract accounts from account api")
				return "", "", "", err
			}
			result = id
			accKind = kind
			accName = name
		}

	}

	return result, accKind, accName, nil

}

func performPlatformAuthRequest(req *http.Request) ([]byte, http.Header, int, error) {
	client := &http.Client{
		Timeout: platformAuthRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPlatformAuthResponseBytes+1))
	if err != nil {
		return nil, nil, 0, err
	}
	if len(body) > maxPlatformAuthResponseBytes {
		return nil, nil, 0, fmt.Errorf("control-platform account response exceeds %d bytes", maxPlatformAuthResponseBytes)
	}
	return body, resp.Header.Clone(), resp.StatusCode, nil
}

// check the AuthorizeData
func checkIfAuthorized(bodyText []byte) error {

	authMessage := AuthorizeData{}
	err := json.Unmarshal(bodyText, &authMessage)
	if err != nil {
		return fmt.Errorf("can not read the reponse body")
	}
	if authMessage.Message == "Unauthorized" {
		return errPlatformUnauthorized
	}
	return nil
}
