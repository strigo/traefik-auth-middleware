package traefik_auth_middleware

import (
	"fmt"
	"sync"
	"time"
)

const SIZE = 1024

type Cache struct {
	sync.RWMutex

	dirty map[string]Token
}

// Get token from cache. If token not found return status false.
func (c *Cache) Get(key string) (token Token, ok bool) {
	c.RLock()
	token, ok = c.dirty[key]
	c.RUnlock()
	return token, ok
}

// Store a token inside cache
func (c *Cache) Store(key string, t Token) {
	c.Lock()
	if c.dirty == nil {
		c.dirty = make(map[string]Token, SIZE)
	}
	c.dirty[key] = t
	c.Unlock()
}

// Clears cache of any expired tokens
func (c *Cache) ClearExpired() {
	c.Lock()
	for k, v := range c.dirty {
		if v.ExpirationTime.Before(time.Now()) {
			fmt.Println("deleting")
			delete(c.dirty, k)
		}
	}
	c.Unlock()
}
