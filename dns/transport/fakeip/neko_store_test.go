package fakeip_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// a store over the cache file at path, as a core starts it; close stops both as the core does (the store first);
// crash closes the file only, once its writes are in, as a core ended without the store's own save
func nekoStore(t *testing.T, path string) (*fakeip.Store, func()) {
	store, stop, _ := nekoStoreCrash(t, path)
	return store, stop
}

func nekoStoreCrash(t *testing.T, path string) (*fakeip.Store, func(), func()) {
	t.Helper()
	cacheFile := cachefile.New(context.Background(), logger.NOP(), option.CacheFileOptions{Enabled: true, Path: path, StoreFakeIP: true})
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	if err := cacheFile.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	store := fakeip.NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"))
	if err := store.Start(); err != nil {
		t.Fatal(err)
	}
	return store, func() {
			store.Close()
			scope.Close()
		}, func() {
			scope.Close()
		}
}

// New names are given at once (the write goes on in the background), looked up before the write lands, and found
// by the next core on the same file: every address the last one gave, with the range going on from where it was.
func TestNekoFakeIPStoredAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	store, stop := nekoStore(t, path)
	given := map[netip.Addr]string{}
	started := time.Now()
	for i := range 100 {
		domain := fmt.Sprintf("n%d.example", i)
		address, err := store.Create(domain, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := store.Lookup(address); !ok || got != domain {
			t.Fatalf("%s: %q %v right after it was given", address, got, ok)
		}
		given[address] = domain
	}
	// one write a name under the lock waited bbolt's batch delay (10 ms) each: a second at least
	if took := time.Since(started); took > 500*time.Millisecond {
		t.Fatalf("100 new names took %s", took)
	}
	stop()

	store, stop = nekoStore(t, path)
	defer stop()
	for address, domain := range given {
		if got, ok := store.Lookup(address); !ok || got != domain {
			t.Fatalf("%s after the restart: %q %v, want %s", address, got, ok, domain)
		}
	}
	again, _ := store.Create("n7.example", false)
	if given[again] != "n7.example" {
		t.Fatalf("n7.example again: %s, another address", again)
	}
	fresh, _ := store.Create("fresh.example", false)
	if _, taken := given[fresh]; taken {
		t.Fatalf("fresh.example got %s, an address the last core gave", fresh)
	}
}

// The core ended without the store's own save (killed, OOM) right after new names: the range pointer went to the
// file with each address, so the next core gives none of those addresses to another name.
func TestNekoFakeIPAbruptEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	store, _, crash := nekoStoreCrash(t, path)
	given := map[netip.Addr]string{}
	for i := range 50 {
		domain := fmt.Sprintf("n%d.example", i)
		address, err := store.Create(domain, false)
		if err != nil {
			t.Fatal(err)
		}
		given[address] = domain
	}
	crash()

	store, stop := nekoStore(t, path)
	defer stop()
	for address, domain := range given {
		if got, ok := store.Lookup(address); !ok || got != domain {
			t.Fatalf("%s after an abrupt end: %q %v, want %s", address, got, ok, domain)
		}
	}
	for i := range 50 {
		fresh, _ := store.Create(fmt.Sprintf("fresh%d.example", i), false)
		if old, taken := given[fresh]; taken {
			t.Fatalf("fresh%d.example got %s, %s's address before the abrupt end", i, fresh, old)
		}
	}
}

// ClearFakeIP: the names asked leave the file when the VPN stops; a core started on it begins the range anew.
func TestNekoFakeIPCleared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	if err := cachefile.ClearFakeIP(path); err != nil {
		t.Fatalf("no file yet: %v", err)
	}
	store, stop := nekoStore(t, path)
	address, _ := store.Create("secret.example", false)
	stop()
	if err := cachefile.ClearFakeIP(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret.example") {
		t.Fatal("the name is still in the file's bytes")
	}
	store, stop = nekoStore(t, path)
	defer stop()
	if got, ok := store.Lookup(address); ok {
		t.Fatalf("%s still stands for %q", address, got)
	}
}
