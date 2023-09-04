package traefik_auth_middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	CF_HEADER = "Cf-Access-Jwt-Assertion"
	NOMAD_HEADER = "X-Nomad-Token"
)

var (
	Cache map[string]Token
)

type Config struct {
	NomadEndpoint string `json:"nomadEndpoint,omitempty"`
	AuthMethodName string `json:"authMethodName,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		NomadEndpoint: "http://localhost:4646",
	}
}

type Plugin struct {
	next     http.Handler
	name     string
	config   *Config
	client   *http.Client
	logger   *log.Logger
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	Cache = make(map[string]Token, 1024)
	return &Plugin{
		next: next,
		name: name,
		config: config,
		client: &http.Client{},
		logger: log.New(os.Stderr, fmt.Sprintf("[%v] " ,name), log.Ltime | log.Lmicroseconds),
	}, nil
}

// Handle HTTP request in the middleware chain
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cfjwt :=req.Header.Get(CF_HEADER)
	if cfjwt == "" {
		p.logger.Println("No Cf-Access-Jwt-Assertion header found")
		p.next.ServeHTTP(rw, req)
		return
	}

	// Check if token already cached and valid. If not, reach out to Nomad to
	// get a new one and cache it.
	token, ok := Cache[cfjwt]
	if !ok || time.Now().UTC().After(token.ExpirationTime) {
		var err error

		p.logger.Println("Assertion not cached - connecting to Nomad")
		token, err = p.login(cfjwt)
		if err != nil {
			// in case of error, proceed to next without doing anything
			p.logger.Printf("Nomad error: %v\n", err)
			p.next.ServeHTTP(rw, req)
			return
		}

		Cache[cfjwt] = token
	}

	req.Header.Set(NOMAD_HEADER, token.SecretID)

	p.next.ServeHTTP(rw, req)
}

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
