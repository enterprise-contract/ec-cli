/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// HTTP protocol stubbing using WireMock (https://wiremock.org/)
package wiremock

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path"

	"cuelang.org/go/pkg/strings"
	"github.com/cucumber/godog"
	"github.com/docker/go-connections/nat"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/log"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	wiremock "github.com/walkerus/go-wiremock"
)

type key int

const (
	wireMockKey    key                          = iota // Key under which the WireMock client is held in the Context
	wireMockURLKey                                     // URL of the WireMock instance, usually http://localhost:port where the port is NAT-ed by exposing the port 8080 of the container
	wireMockImage  = "wiremock/wiremock:2.33.2"        // container image used to run WireMock
)

// to make it simpler on imports in the clients of this package,
// we re-expose functions from the wiremock package, add others
// as needed
var Get = wiremock.Get
var Post = wiremock.Post
var URLEqualTo = wiremock.URLEqualTo
var URLPathEqualTo = wiremock.URLPathEqualTo

type client struct {
	*wiremock.Client

	url string
}

// newClient creates a new WireMock client, delegating to the wiremock.Client
// with additional methods we require not present there
func newClient(url string) *client {
	w := *wiremock.NewClient(url)

	return &client{url: url, Client: &w}
}

// The result of /__admin/requests/unmatched endpoint
type unmatchedRequest struct {
	URL                 string `json:"url"`
	AbsoluteURL         string `json:"absoluteUrl"`
	Method              string
	Headers             map[string]interface{}
	Body                string
	BrowserProxyRequest bool
	LoggedDate          int64
	LoggedDateString    string
}

// contentTypeFromString returns the content-type part of a MIME media type
// for example given "type/subtype;parameter=value;..." returns "type/subtype"
func contentTypeFromString(s string) string {
	contentType, _, err := mime.ParseMediaType(s)
	if err != nil {
		panic(err)
	}

	return contentType
}

// contentTypeFrom returns the content-type based on the Accept HTTP
// header of a HTTP request, given that HTTP headers can be multi-valued
// it either returns the single value or the first value of many
// "&lt;unknown&gt;" is returned when the Accept HTTP header is not
// present or it contains no values
func contentTypeFrom(u unmatchedRequest) string {
	for key, value := range u.Headers {
		if strings.ToLower(key) == "accept" {
			switch v := value.(type) {
			case string:
				return contentTypeFromString(v)
			case []interface{}:
				if len(v) >= 1 {
					return contentTypeFromString(fmt.Sprintf("%s", v[0]))
				}
			}
		}
	}

	return "<unknown>"
}

// String formats the unmatched request and generates a snippet to help
// stub the request, useful when reporting unmatched requests i.e. those
// that have been received but no stubbing was defined
func (u unmatchedRequest) String() string {
	str := fmt.Sprintf("Found unmatched %s request to %s\n", u.Method, u.URL)

	if u.Body != "" {
		str += "The request contained this HTTP body:\n" + u.Body
	}

	str += fmt.Sprintf(`Stub it by adding:
wiremock.StubFor(ctx, wiremock.%s(wiremock.URLPathEqualTo("%s")).
	WillReturn("<body>",
		map[string]string{"Content-Type": "%s"},
		200,
	))`, strings.ToTitle(strings.ToLower(u.Method)), u.URL, contentTypeFrom(u))

	return str
}

// UnmatchedRequests queries the WireMock admin API for any unmatched requests
// i.e. those that have been received but no stubbing was defined and returns
// them
func (c *client) UnmatchedRequests() ([]unmatchedRequest, error) {
	res, err := http.Get(fmt.Sprintf("%s/__admin/requests/unmatched", c.url))
	if err != nil {
		return nil, fmt.Errorf("unmatched requests: %s", err.Error())
	}
	defer res.Body.Close()

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unmatched requests: read response error: %s", err.Error())
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unmatched requests: bad response status: %d, response: %s", res.StatusCode, string(bodyBytes))
	}

	var unmatchedRequestsResponse struct {
		Requests []unmatchedRequest `json:"requests"`
	}

	err = json.Unmarshal(bodyBytes, &unmatchedRequestsResponse)
	if err != nil {
		return nil, fmt.Errorf("unmatched requests: read json error: %s", err.Error())
	}

	return unmatchedRequestsResponse.Requests, nil
}

// StartWiremock starts the WireMock instance if one is not already running
func StartWiremock(ctx context.Context) (context.Context, error) {
	if ctx.Value(wireMockKey) != nil {
		// we already stored the key in this Context, a WireMock instance
		// must be running already
		return ctx, nil
	}

	// cwd is the directory where the test is run from i.e. $GITROOT/internal/acceptance
	cwd, err := os.Getwd()
	if err != nil {
		return ctx, err
	}

	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        wireMockImage,
		ExposedPorts: []string{"8080/tcp", "8443/tcp"},
		WaitingFor:   wait.ForHTTP("/__admin/mappings").WithPort(nat.Port("8080/tcp")),
		Binds:        []string{fmt.Sprintf("%s:/recordings:Z", path.Join(cwd, "wiremock", "recordings"))}, // relative to the running test, i.e. $GITROOT/internal/acceptance
		Cmd: []string{
			"--root-dir=/recordings",
		},
	})

	w, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log.LoggerFor(ctx),
	})
	if err != nil {
		return ctx, err
	}

	port, err := w.MappedPort(ctx, nat.Port("8080/tcp"))
	if err != nil {
		return ctx, err
	}

	url := fmt.Sprintf("http://localhost:%d", port.Int())
	client := newClient(url)

	ctx = context.WithValue(ctx, wireMockKey, client)
	ctx = context.WithValue(ctx, wireMockURLKey, url)

	return ctx, nil
}

// wiremockFrom returns the client used to interact with the WireMock admin API
func wiremockFrom(ctx context.Context) *client {
	w, ok := ctx.Value(wireMockKey).(*client)
	if !ok {
		panic("expecting WireMock client in context, found none or of wrong type")
	}

	return w
}

// StubFor delegates to the wiremock.StubFor of the WireMock instance assigned
// to the provided Context
func StubFor(ctx context.Context, stubRule *wiremock.StubRule) {
	w := wiremockFrom(ctx)

	if err := w.StubFor(stubRule); err != nil {
		panic(err)
	}
}

// Endpoint returns the URL of the WireMock instance
func Endpoint(ctx context.Context) string {
	return ctx.Value(wireMockURLKey).(string)
}

// AddStepsTo makes sure that nay unmatched requests, i.e. requests that are not
// stubbed get reported at the end of a scenario run
// TODO: reset stub state after the scenario (given not persisted flag is set)
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.After(func(ctx context.Context, finished *godog.Scenario, scenarioErr error) (context.Context, error) {
		w := wiremockFrom(ctx)

		unmatched, err := w.UnmatchedRequests()
		if err != nil {
			return ctx, err
		}

		if len(unmatched) == 0 {
			return ctx, nil
		}

		logger := log.LoggerFor(ctx)
		logger.Log("Found unmatched WireMock requests:")
		for i, u := range unmatched {
			logger.Logf("[%d]: %s", i, u)
		}

		return ctx, err
	})
}
