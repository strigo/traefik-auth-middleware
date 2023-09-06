package traefik_auth_middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Token struct {
	AccessorID     string    `json:"AccessorID"`
	SecretID       string    `json:"SecretID"`
	ExpirationTime time.Time `json:"ExpirationTime"`
}

type LoginRequestBody struct {
	AuthMethodName string
	LoginToken     string
}

// Login to Nomad with jwt and return a Token
func (p *Plugin) login(jwt string) (Token, error) {
	req_body, err := json.Marshal(LoginRequestBody{p.config.AuthMethodName, jwt})
	if err != nil {
		return Token{}, err
	}

	url, err := url.JoinPath(p.config.NomadEndpoint, "v1", "acl/login")
	if err != nil {
		return Token{}, err
	}

	resp, err := p.client.Post(url, "application/json", bytes.NewReader(req_body))
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("unexpected return code (%v) from nomad", resp.StatusCode)
	}

	resp_body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Token{}, err
	}
	var token Token
	json.Unmarshal(resp_body, &token)

	return token, nil
}
