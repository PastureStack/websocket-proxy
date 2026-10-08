package delegation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// FailureReporter proves both possession of a stream grant and the currently
// authenticated backend connection ticket. It cannot choose an outcome or
// exercise any general Agent API authority.
type FailureReporter struct {
	Endpoint string
	Client   *http.Client
}

func NewFailureReporter(engine string) *FailureReporter {
	reporter := &FailureReporter{Client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	target, err := url.Parse(engine)
	if err == nil && (target.Scheme == "http" || target.Scheme == "https") && target.Host != "" && target.User == nil && target.RawQuery == "" && target.Fragment == "" {
		target.Path, target.RawPath = "/v2-beta/apiKeyDelegationFailure/report", ""
		reporter.Endpoint = target.String()
	}
	return reporter
}

func (reporter *FailureReporter) Report(token, backendToken string) bool {
	if reporter == nil || reporter.Endpoint == "" || reporter.Client == nil || token == "" || backendToken == "" || len(token) > MaxTokenBytes || len(backendToken) > MaxTokenBytes {
		return false
	}
	body, _ := json.Marshal(map[string]string{"token": token, "backendToken": backendToken})
	// A client disconnect must not cancel an already observed server denial.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, reporter.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := reporter.Client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(content) > 4096 || response.StatusCode != http.StatusOK {
		return false
	}
	var result map[string]interface{}
	return json.Unmarshal(content, &result) == nil && result["accepted"] == true
}
