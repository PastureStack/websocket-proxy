package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/filters"
	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/model"
	log "github.com/sirupsen/logrus"
)

const (
	interceptorType            = "http"
	maxFilterResponseBodyBytes = 4 << 20
	maxFilterRequestBodyBytes  = 5 << 20
	defaultFilterTimeout       = 15
	maximumFilterTimeout       = 120
)

type GenericHTTPFilter struct {
	client *http.Client
}

func (f *GenericHTTPFilter) GetType() string {
	return interceptorType
}

func NewFilter() (filters.APIFilter, error) {
	httpFilter := &GenericHTTPFilter{
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	log.Infof("Configured %s API filter", httpFilter.GetType())

	return httpFilter, nil
}

func (f *GenericHTTPFilter) ProcessFilter(filter model.FilterData, input model.APIRequestData) (model.APIRequestData, error) {
	output := model.APIRequestData{}
	bodyContent, err := json.Marshal(input)
	if err != nil {
		return output, err
	}
	if len(bodyContent) > maxFilterRequestBodyBytes {
		return output, fmt.Errorf("API filter request exceeds %d bytes", maxFilterRequestBodyBytes)
	}

	log.Debugf("Request => bytes=%d headers=%v bodyKeys=%v", len(bodyContent), headerKeys(input.Headers), bodyKeys(input.Body))

	endpoint, err := validFilterEndpoint(filter.Endpoint)
	if err != nil {
		return output, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader(bodyContent))
	if err != nil {
		return output, err
	}
	//sign the body
	if filter.SecretToken != "" {
		signature := filters.SignString(bodyContent, []byte(filter.SecretToken))
		req.Header.Set(model.SignatureHeader, signature)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(bodyContent)))

	tout := defaultFilterTimeout
	if filter.Timeout != "0" && filter.Timeout != "" {
		parsed, parseErr := strconv.Atoi(filter.Timeout)
		if parseErr == nil && parsed > 0 && parsed <= maximumFilterTimeout {
			tout = parsed
		}
	}
	requestClient := *f.client
	requestClient.Timeout = time.Second * time.Duration(tout)
	resp, err := requestClient.Do(req)
	if err != nil {
		return output, err
	}
	log.Debugf("Response Status <= %s", resp.Status)
	defer resp.Body.Close()

	byteContent, err := io.ReadAll(io.LimitReader(resp.Body, maxFilterResponseBodyBytes+1))
	if err != nil {
		return output, err
	}
	if len(byteContent) > maxFilterResponseBodyBytes {
		return output, fmt.Errorf("API filter response exceeds %d bytes", maxFilterResponseBodyBytes)
	}

	log.Debugf("Response <= status=%d bytes=%d", resp.StatusCode, len(byteContent))

	if len(byteContent) > 0 {
		if err := json.Unmarshal(byteContent, &output); err != nil {
			return output, err
		}
	}
	output.Status = resp.StatusCode

	return output, nil
}

func validFilterEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint == nil {
		return nil, fmt.Errorf("invalid API filter endpoint")
	}
	if (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, fmt.Errorf("API filter endpoint must be HTTP(S), include a host, and contain no credentials or fragment")
	}
	return endpoint, nil
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
