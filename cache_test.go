package traefik_auth_middleware

import (
	"testing"
	"time"
)

func TestEmpty(t *testing.T) {
	cache := Cache{}

	_, ok := cache.Get("foo")
	if ok {
		t.Error("Expected get on empty cache to be empty, but got ok")
	}

	// check that call to ClearExpired doesn't blow up if cache empty
	cache.ClearExpired()
}

func TestCache(t *testing.T) {
	cache := Cache{}

	items := map[string]Token{
		"foo": {"fooAccessor", "fooSecret", time.Now()},
		"bar": {"barAccessor", "barSecret", time.Now()},
		"baz": {"bazAccessor", "bazSecret", time.Now()},
	}

	for k, v := range items {
		cache.Store(k, v)
	}

	for k, v := range items {
		rv, ok := cache.Get(k)
		if !ok {
			t.Errorf("exected %v to be found in cache, but didn't", k)
		}
		if rv != v {
			t.Errorf("exected %v but got %v", v, rv)
		}
	}
}

func TestCacheExpiry(t *testing.T) {
	cache := Cache{}

	items := map[string]Token{
		"foo": {"fooAccessor", "fooSecret", time.Now().Add(time.Hour)},
		"bar": {"barAccessor", "barSecret", time.Now().Add(time.Hour)},
		"baz": {"bazAccessor", "bazSecret", time.Now()},
	}

	for k, v := range items {
		cache.Store(k, v)
	}

	cache.ClearExpired()

	if _, ok := cache.Get("baz"); ok {
		t.Errorf("expired item still returned from cache")
	}

}
