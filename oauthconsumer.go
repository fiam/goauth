package oauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type OAuthConsumer struct {
	Service          string
	RequestTokenURL  string
	AccessTokenURL   string
	AuthorizationURL string
	ConsumerKey      string
	ConsumerSecret   string
	CallBackURL      string
	requestTokens    []*RequestToken
	AdditionalParams Params
}

func (oc *OAuthConsumer) parameters(params Params) Params {
	var p Params
	// Add required OAuth params
	p.Add(&Pair{Key: "oauth_version", Value: "1.0"})
	p.Add(&Pair{Key: "oauth_timestamp", Value: strconv.FormatInt(time.Now().Unix(), 10)})
	p.Add(&Pair{Key: "oauth_consumer_key", Value: oc.ConsumerKey})
	p.Add(&Pair{Key: "oauth_nonce", Value: strconv.FormatInt(rand.Int63(), 10)})
	p.Add(&Pair{Key: "oauth_signature_method", Value: "HMAC-SHA1"})
	for _, v := range params {
		p.Add(v)
	}
	return p
}

func (oc *OAuthConsumer) sign(method string, url string, secret string, p Params) string {
	base := fmt.Sprintf("%s&%s&%s", method, Encode(url), Encode(p.Encode()))
	key := Encode(oc.ConsumerSecret) + "&" + Encode(secret)
	// Generate Signature
	return oc.digest(key, base)
}

func (oc *OAuthConsumer) headers(method string, url string, secret string, p Params) map[string]string {
	signature := oc.sign(method, url, secret, p)
	// Build Auth Header
	var oauth_headers []string
	for _, v := range p {
		if strings.HasPrefix(v.Key, "oauth") {
			oauth_headers = append(oauth_headers, v.EncodeQuoted())
		}
	}
	// Add the signature
	s := &Pair{Key: "oauth_signature", Value: signature}
	oauth_headers = append(oauth_headers, s.Encode())
	sort.Strings(oauth_headers)
	return map[string]string{
		"Authorization": "OAuth " + strings.Join(oauth_headers, ", "),
	}
}

// GetRequestAuthorizationURL Returns the URL for the visitor to Authorize the Access
func (oc *OAuthConsumer) GetRequestAuthorizationURL() (string, *RequestToken, error) {
	p := oc.parameters(NewParams("oauth_callback", oc.CallBackURL))
	for _, v := range oc.AdditionalParams {
		p.Add(v)
	}
	headers := oc.headers("GET", oc.RequestTokenURL, "", p)
	resp, err := get(oc.RequestTokenURL, headers)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		// OAuth service returned an error
		return "", nil, fmt.Errorf("oAuth service returned non-200 status code %d: s", resp.StatusCode, s)
	}
	values, err := url.ParseQuery(s)
	if err != nil {
		return "", nil, err
	}
	rt := &RequestToken{
		Token:  values.Get("oauth_token"),
		Secret: values.Get("oauth_token_secret"),
	}

	if rt.Token == "" || rt.Secret == "" {
		return "", nil, fmt.Errorf("can't parse token from %q", s)
	}
	oc.appendRequestToken(rt)
	return oc.AuthorizationURL + "?oauth_token=" + rt.Token, rt, nil

}

// GetAccessToken gets the access token for the response from the Authorization URL
func (oc *OAuthConsumer) GetAccessToken(token string, verifier string) (*AccessToken, error) {

	var secret string
	// Match the RequestToken by Token
	for _, v := range oc.requestTokens {
		if v.Token == token || v.Token == Encode(token) {
			secret = v.Secret
		}
	}

	p := oc.parameters(NewParams(
		"oauth_token", token,
		"oauth_verifier", verifier,
	))

	headers := oc.headers("POST", oc.AccessTokenURL, secret, p)
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	// Action the POST to get the AccessToken
	resp, err := post(oc.AccessTokenURL, headers, strings.NewReader(p.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oAuth service returned non-200 status code %d: s", resp.StatusCode, s)
	}
	values, err := url.ParseQuery(s)
	if err != nil {
		return nil, err
	}
	at := &AccessToken{
		Service:  oc.Service,
		Token:    values.Get("oauth_token"),
		Secret:   values.Get("oauth_token_secret"),
		Verifier: verifier,
	}
	if at.Token == "" || at.Secret == "" {
		return nil, fmt.Errorf("can't parse token from %q", s)
	}
	return at, nil

}

// OAuthRequestGet return the response via a GET for the url with the AccessToken passed
func (oc *OAuthConsumer) Get(url string, fparams Params, at *AccessToken) (r *http.Response, err error) {
	return oc.oAuthRequest(url, fparams, at, "GET")
}

// OAuthRequest returns the response via a POST for the url with the AccessToken passed & the Form params passsed in fparams
func (oc *OAuthConsumer) Post(url string, fparams Params, at *AccessToken) (r *http.Response, err error) {
	return oc.oAuthRequest(url, fparams, at, "POST")
}

func (oc *OAuthConsumer) oAuthRequest(url string, p Params, at *AccessToken, method string) (r *http.Response, err error) {

	signed := oc.parameters(NewParams("oauth_token", at.Token))
	for _, v := range p {
		signed.Add(v)
	}
	var secret string
	if at != nil {
		secret = at.Secret
	}
	headers := oc.headers(method, url, secret, signed)
	if method == "GET" {
		// return Get response
		if p != nil {
			return get(url+"?"+p.Encode(), headers)
		}
		return get(url, headers)
	}

	headers["Content-Type"] = "application/x-www-form-urlencoded"
	// return POSTs response
	if p != nil {
		return post(url, headers, strings.NewReader(p.Encode()))
	}
	return post(url, headers, nil)

}

// digest Generates a HMAC-1234 for the signature
func (oc *OAuthConsumer) digest(key string, m string) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(m))
	return base64encode(h.Sum(nil))
}

// appendRequestToken adds the Request Tokens to a localy temp collection
func (oc *OAuthConsumer) appendRequestToken(token *RequestToken) {

	// TODO: Proper locking
	oc.requestTokens = append(oc.requestTokens, token)
}
