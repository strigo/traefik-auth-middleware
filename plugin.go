package traefik_auth_middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	CF_HEADER             = "Cf-Access-Jwt-Assertion"
	NOMAD_HEADER          = "X-Nomad-Token"
	CACHE_CLEAR_CYCLE_HRS = 1
)

var tokenCache Cache

type Config struct {
	NomadEndpoint  string `json:"nomadEndpoint,omitempty"`
	AuthMethodName string `json:"authMethodName,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		NomadEndpoint: "http://localhost:4646",
	}
}

type Plugin struct {
	next   http.Handler
	name   string
	config *Config
	client *http.Client
	logger *log.Logger
}

// Initiate new plugin instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Start cache clearing cycle to remove any expired tokens
	go func() {
		for {
			time.Sleep(CACHE_CLEAR_CYCLE_HRS * time.Hour)
			tokenCache.ClearExpired()
		}
	}()

	return &Plugin{
		next:   next,
		name:   name,
		config: config,
		client: &http.Client{},
		logger: log.New(os.Stderr, fmt.Sprintf("[%v] ", name), log.Ltime|log.Lmicroseconds),
	}, nil
}

// Handle HTTP request in the middleware chain
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cfjwt := req.Header.Get(CF_HEADER)
	if cfjwt == "" {
		p.logger.Println("No Cf-Access-Jwt-Assertion header found")
		p.next.ServeHTTP(rw, req)
		return
	}

	// Check if token already cached and valid. If not, reach out to Nomad to
	// get a new one and cache it.
	token, ok := tokenCache.Get(cfjwt)
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

		tokenCache.Store(cfjwt, token)
	}

	req.Header.Set(NOMAD_HEADER, token.SecretID)

	p.next.ServeHTTP(rw, req)
}
