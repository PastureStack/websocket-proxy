package apiinterceptor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/filters"
	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/filters/auth"
	httpfilter "github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/filters/http"
	"github.com/PastureStack/websocket-proxy/proxy/apiinterceptor/model"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const maxAPIInterceptorConfigBytes = 4 << 20

// destination defines the properties of a destination
type destination struct {
	DestinationURL string   `json:"DestinationURL"`
	Paths          []string `json:"Paths"`
}

// configFileFields stores filter config
type configFileFields struct {
	RequestInterceptors []model.FilterData
	Destinations        []destination
}

func newRouter(configFile string, platformAddr string, routerSetter routerSetter) (http.Handler, error) {
	if platformAddr == "" {
		return nil, fmt.Errorf("no PlatformAddr is set for forwarding control-platform API requests")
	}

	platformURL, err := url.Parse("http://" + platformAddr)
	if err != nil || platformURL.Host == "" || platformURL.User != nil || platformURL.Path != "" ||
		platformURL.RawQuery != "" || platformURL.Fragment != "" || platformURL.Opaque != "" {
		return nil, fmt.Errorf("invalid control-platform address")
	}

	director := func(req *http.Request) {
		req.URL.Scheme = platformURL.Scheme
		req.URL.Host = platformURL.Host
	}
	platformRevProxy := &httputil.ReverseProxy{
		Director:      director,
		FlushInterval: time.Millisecond * 100,
	}

	apiFilters, err := loadAPIFilters()
	if err != nil {
		return nil, fmt.Errorf("couldn't load API filters: %w", err)
	}
	return buildRouter(configFile, platformRevProxy, apiFilters, routerSetter)
}

func buildRouter(configFile string, platformRevProxy *httputil.ReverseProxy, apiFilters map[string]filters.APIFilter, routerSetter routerSetter) (http.Handler, error) {
	pathPreFilters := map[string][]model.FilterData{}
	pathDestinations := map[string]http.Handler{}
	configFields := configFileFields{}

	if configFile != "" {
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			// Treat a missing file as empty configuration; the control plane removes it when no filters are configured.
			log.Debugf("config.json file not found %v", configFile)
		} else {
			configContent, err := readBoundedConfigFile(configFile)
			if err != nil {
				return nil, fmt.Errorf("error reading API interceptor config at %q: %w", configFile, err)
			}

			err = json.Unmarshal(configContent, &configFields)
			if err != nil {
				return nil, fmt.Errorf("couldn't decode API interceptor config: %w", err)
			}

			for _, filter := range configFields.RequestInterceptors {
				for _, path := range filter.Paths {
					pathPreFilters[path] = append(pathPreFilters[path], filter)
				}
			}

			for _, destination := range configFields.Destinations {
				//build the pathDestinations map
				destProxy, err := newProxy(destination.DestinationURL)
				if err != nil {
					return nil, fmt.Errorf("couldn't load configured proxy destination: %w", err)
				}
				for _, path := range destination.Paths {
					pathDestinations[path] = destProxy
				}
			}
		}
	}

	copyAPIFilters := map[string]filters.APIFilter{}
	for k, v := range apiFilters {
		copyAPIFilters[k] = v
	}

	interceptor := &interceptor{
		configFile:           configFile,
		platformReverseProxy: platformRevProxy,
		apiFilters:           copyAPIFilters,
		pathDestinations:     pathDestinations,
		pathPreFilters:       pathPreFilters,
		routerSetter:         routerSetter,
	}

	router := mux.NewRouter().StrictSlash(false)
	for _, filter := range configFields.RequestInterceptors {
		//build interceptor Paths
		for _, path := range filter.Paths {
			for _, method := range filter.Methods {
				log.Infof("Adding route: %v %v", strings.ToUpper(method), path)
				router.Methods(strings.ToUpper(method)).Path(path).HandlerFunc(http.HandlerFunc(interceptor.intercept))
			}
		}
	}

	router.Methods("POST").Path("/v1-api-interceptor/reload").HandlerFunc(http.HandlerFunc(interceptor.reload))
	router.NotFoundHandler = http.HandlerFunc(interceptor.platformProxy)
	var routes []*mux.Route
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		routes = append(routes, route)
		return nil
	})
	interceptor.routes = routes
	return router, nil
}

func readBoundedConfigFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxAPIInterceptorConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxAPIInterceptorConfigBytes {
		return nil, fmt.Errorf("API interceptor configuration exceeds %d bytes", maxAPIInterceptorConfigBytes)
	}
	return contents, nil
}

func loadAPIFilters() (map[string]filters.APIFilter, error) {
	apiFilters := make(map[string]filters.APIFilter)

	httpFilter, err := httpfilter.NewFilter()
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize HTTP API filter: %w", err)
	}
	apiFilters[httpFilter.GetType()] = httpFilter

	tokenFilter, err := auth.NewFilter()
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize authentication API filter: %w", err)
	}
	apiFilters[tokenFilter.GetType()] = tokenFilter

	return apiFilters, nil
}

func newProxy(target string) (*httputil.ReverseProxy, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid destination URL")
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("destination URL must be HTTP(S), include a host, and contain no credentials or fragment")
	}
	newProxy := httputil.NewSingleHostReverseProxy(parsed)
	newProxy.FlushInterval = time.Millisecond * 100
	return newProxy, nil
}
