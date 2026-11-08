package fakeip_test

import (
	"context"
	"encoding/binary"
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

// A cache file bbolt cannot read (corrupt pages make it panic): ClearFakeIP removes it, as the core resets one,
// instead of a panic through gomobile at every start of the VPN.
func TestNekoFakeIPClearCorrupted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	store, stop := nekoStore(t, path)
	for i := range 20 {
		store.Create(fmt.Sprintf("n%d.example", i), false)
	}
	stop()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := os.Getpagesize()
	// every page after the meta pages garbage (bbolt's error at open), or each page but the meta and freelist ones
	// (a panic of bbolt's reading the buckets)
	for _, keep := range []func(n int) bool{
		func(n int) bool { return n < 2 },
		func(n int) bool { return n < 2 || nekoFreelistPage(raw, page) == n },
	} {
		bad := append([]byte(nil), raw...)
		for i := 2 * page; i < len(bad); i++ {
			if !keep(i / page) {
				bad[i] = 0xa5
			}
		}
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cachefile.ClearFakeIP(path); err != nil {
			t.Fatalf("a corrupt file: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			left, _ := os.ReadFile(path)
			if strings.Contains(string(left), "n7.example") {
				t.Fatal("a corrupt file left with the names in it")
			}
		}
	}
}

// nekoFreelistPage is the freelist's page in the newer meta page of a bbolt file (meta: magic, version, page size,
// flags, root bucket of 16 bytes, freelist, ... after the 16-byte page header), -1 when none.
func nekoFreelistPage(raw []byte, page int) int {
	freelist, txid := -1, uint64(0)
	for m := 0; m < 2; m++ {
		meta := raw[m*page+16:]
		if len(meta) < 64 {
			continue
		}
		id := binary.LittleEndian.Uint64(meta[48:56])
		if id >= txid {
			txid = id
			freelist = int(binary.LittleEndian.Uint64(meta[32:40]))
		}
	}
	return freelist
}

// A cache file cut short (a crash mid-write, a full disk): bbolt reads pages past its end, inside the mapping, and
// the read faults (SIGBUS); ClearFakeIP removes the file instead of the process dying.
func TestNekoFakeIPClearTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")
	store, stop := nekoStore(t, path)
	for i := range 3000 {
		store.Create(fmt.Sprintf("name-%d.example", i), false)
	}
	stop()
	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := os.Getpagesize()
	for _, pages := range []int{3, 4, 6, len(whole) / page / 2, len(whole)/page - 1} {
		if pages < 3 || pages*page >= len(whole) {
			continue
		}
		if err := os.WriteFile(path, whole[:pages*page], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cachefile.ClearFakeIP(path); err != nil {
			t.Logf("cut at %d pages: %v", pages, err)
		}
		if _, err := os.Stat(path); err == nil {
			left, _ := os.ReadFile(path)
			if strings.Contains(string(left), "name-7.example") {
				t.Fatalf("cut at %d pages: the names left in the file", pages)
			}
		}
	}
}

// A branch page whose child is past the file's end, inside bbolt's mapping (the file cut short after a crash; bbolt
// maps it rounded up to a power of two and never checks a page id against its size): the read faults (SIGBUS),
// which only SetPanicOnFault turns into a panic recover sees; ClearFakeIP removes the file.
func TestNekoFakeIPClearFaulting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	store, stop := nekoStore(t, path)
	for i := range 3000 {
		store.Create(fmt.Sprintf("name-%d.example", i), false)
	}
	stop()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	page := os.Getpagesize()
	pages := len(raw) / page
	// cut after the freelist (bbolt loads it at open, under its own SetPanicOnFault) at a size the mapping exceeds
	cut := max(nekoFreelistPage(raw, page)+1, 3)
	for cut < pages && (cut*page)&(cut*page-1) == 0 {
		cut++
	}
	if cut >= pages {
		t.Skipf("no cut below %d pages", pages)
	}
	child := uint64(cut)
	raw = raw[:cut*page]
	pages = cut
	branches := 0
	for n := 2; n < pages; n++ {
		p := raw[n*page:]
		// page header: id (8), flags (2, branch 0x01), count (2), overflow (4); a branch element: pos (4),
		// ksize (4), pgid (8)
		if binary.LittleEndian.Uint64(p) != uint64(n) || binary.LittleEndian.Uint16(p[8:]) != 0x01 || binary.LittleEndian.Uint16(p[10:]) == 0 {
			continue
		}
		binary.LittleEndian.PutUint64(p[16+8:], child)
		branches++
	}
	if branches == 0 {
		t.Skipf("no branch page in %d pages", pages)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cachefile.ClearFakeIP(path); err != nil {
		t.Fatalf("a faulting file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		left, _ := os.ReadFile(path)
		if strings.Contains(string(left), "name-7.example") {
			t.Fatal("a faulting file left with the names in it")
		}
	}
}
