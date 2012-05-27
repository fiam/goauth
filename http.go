package oauth

import (
	"errors"
	"io"
	"net/http"
)

var (
	NoRedirectAllowedError = errors.New("Redirects not allowed with OAuth")
)

func preventRedirect(req *http.Request, via []*http.Request) error {
	return NoRedirectAllowedError
}

func req(url, method string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	client := &http.Client{CheckRedirect: preventRedirect}
	return client.Do(req)
}

func get(url string, headers map[string]string) (*http.Response, error) {
	return req(url, "GET", headers, nil)
}

func post(url string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return req(url, "POST", headers, body)
}
