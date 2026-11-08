package cachefile

import (
	"errors"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const fakeipBucketPrefix = "fakeip_"

var (
	bucketFakeIP        = []byte(fakeipBucketPrefix + "address")
	bucketFakeIPDomain4 = []byte(fakeipBucketPrefix + "domain4")
	bucketFakeIPDomain6 = []byte(fakeipBucketPrefix + "domain6")
	keyMetadata         = []byte(fakeipBucketPrefix + "metadata")
)

func (c *CacheFile) FakeIPMetadata() *adapter.FakeIPMetadata {
	var metadata adapter.FakeIPMetadata
	err := c.batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return os.ErrNotExist
		}
		metadataBinary := bucket.Get(keyMetadata)
		if len(metadataBinary) == 0 {
			return os.ErrInvalid
		}
		// neko: kept, not deleted on read: FakeIPStoreAsyncWithMetadata writes it in the transaction of each address,
		// so it never lags what the file holds, an abrupt end of the core included
		return metadata.UnmarshalBinary(metadataBinary)
	})
	if err != nil {
		return nil
	}
	return &metadata
}

func (c *CacheFile) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	return c.batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
		if err != nil {
			return err
		}
		metadataBinary, err := metadata.MarshalBinary()
		if err != nil {
			return err
		}
		return bucket.Put(keyMetadata, metadataBinary)
	})
}

func (c *CacheFile) FakeIPSaveMetadataAsync(metadata *adapter.FakeIPMetadata) {
	c.saveMetadataAccess.Lock()
	defer c.saveMetadataAccess.Unlock()
	c.saveMetadata = metadata
	if c.saveMetadataTimer == nil {
		c.saveMetadataTimer = time.AfterFunc(C.FakeIPMetadataSaveInterval, func() {
			c.saveMetadataAccess.Lock()
			savedMetadata := c.saveMetadata
			c.saveMetadataAccess.Unlock()
			if savedMetadata != nil {
				_ = c.FakeIPSaveMetadata(savedMetadata)
			}
		})
	} else {
		c.saveMetadataTimer.Reset(C.FakeIPMetadataSaveInterval)
	}
}

func (c *CacheFile) FakeIPStore(address netip.Addr, domain string) error {
	return c.batch(func(tx *bbolt.Tx) error {
		return putFakeIP(tx, address, domain)
	})
}

func putFakeIP(tx *bbolt.Tx, address netip.Addr, domain string) error {
	bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
	if err != nil {
		return err
	}
	oldDomain := bucket.Get(address.AsSlice())
	err = bucket.Put(address.AsSlice(), []byte(domain))
	if err != nil {
		return err
	}
	if address.Is4() {
		bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain4)
	} else {
		bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain6)
	}
	if err != nil {
		return err
	}
	if oldDomain != nil {
		if err := bucket.Delete(oldDomain); err != nil {
			return err
		}
	}
	return bucket.Put([]byte(domain), address.AsSlice())
}

// neko: an address given and the store's range pointer after it, written by one writer in the order given
type fakeIPWrite struct {
	address  netip.Addr
	domain   string
	metadata *adapter.FakeIPMetadata
}

// FakeIPStoreAsyncWithMetadata (neko) keeps the address visible to lookups at once and writes it in the background
// with metadata in one transaction, in the order the addresses were given: whatever ends the core, the file never
// holds an address past the range pointer it holds, so the next core does not give that address to another name.
func (c *CacheFile) FakeIPStoreAsyncWithMetadata(address netip.Addr, domain string, metadata *adapter.FakeIPMetadata, logger logger.Logger) {
	c.saveFakeIPAccess.Lock()
	c.pendFakeIP(address, domain)
	if c.saveFakeIPClosing {
		// the database is closing: kept for lookups until then, not written
		c.saveFakeIPAccess.Unlock()
		return
	}
	c.saveFakeIPQueue = append(c.saveFakeIPQueue, fakeIPWrite{address, domain, metadata})
	start := !c.saveFakeIPWriting
	if start {
		c.saveFakeIPWriting = true
		c.saveFakeIPWait.Add(1)
	}
	c.saveFakeIPAccess.Unlock()
	if start {
		go c.writeFakeIP(logger)
	}
}

// writeFakeIP writes what is queued, all of it in one transaction, until the queue is empty.
func (c *CacheFile) writeFakeIP(logger logger.Logger) {
	defer c.saveFakeIPWait.Done()
	for {
		c.saveFakeIPAccess.Lock()
		queue := c.saveFakeIPQueue
		c.saveFakeIPQueue = nil
		if len(queue) == 0 {
			c.saveFakeIPWriting = false
			c.saveFakeIPAccess.Unlock()
			return
		}
		c.saveFakeIPAccess.Unlock()
		err := c.update(func(tx *bbolt.Tx) error {
			var metadata *adapter.FakeIPMetadata
			for _, w := range queue {
				if err := putFakeIP(tx, w.address, w.domain); err != nil {
					return err
				}
				if w.metadata != nil {
					metadata = w.metadata
				}
			}
			if metadata == nil {
				return nil
			}
			metadataBinary, err := metadata.MarshalBinary()
			if err != nil {
				return err
			}
			return tx.Bucket(bucketFakeIP).Put(keyMetadata, metadataBinary)
		})
		if err != nil {
			logger.Warn("save FakeIP cache: ", err)
		}
		c.saveFakeIPAccess.Lock()
		for _, w := range queue {
			c.unpendFakeIP(w.address, w.domain)
		}
		c.saveFakeIPAccess.Unlock()
	}
}

// pendFakeIP and unpendFakeIP keep an address being written visible to lookups; under saveFakeIPAccess. An entry
// a later address or name replaced stays.
func (c *CacheFile) pendFakeIP(address netip.Addr, domain string) {
	if oldDomain, loaded := c.saveDomain[address]; loaded {
		if address.Is4() {
			delete(c.saveAddress4, oldDomain)
		} else {
			delete(c.saveAddress6, oldDomain)
		}
	}
	c.saveDomain[address] = domain
	if address.Is4() {
		c.saveAddress4[domain] = address
	} else {
		c.saveAddress6[domain] = address
	}
}

func (c *CacheFile) unpendFakeIP(address netip.Addr, domain string) {
	if c.saveDomain[address] == domain {
		delete(c.saveDomain, address)
	}
	if address.Is4() {
		if c.saveAddress4[domain] == address {
			delete(c.saveAddress4, domain)
		}
	} else if c.saveAddress6[domain] == address {
		delete(c.saveAddress6, domain)
	}
}

// ClearFakeIP (neko) removes FakeDNS's addresses and the names they stand for from the cache file at path, which no
// core may have open: they are kept for a restart of the core under a running VPN, and are a record of the names
// asked. bbolt leaves a deleted bucket's bytes in its free pages, so what remains (rule-sets, selections) is copied
// to a new file that replaces this one. No file, or no FakeDNS in it: nothing to do.
func ClearFakeIP(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	db, err := bbolt.Open(path, 0o666, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return err
	}
	found := false
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketFakeIP, bucketFakeIPDomain4, bucketFakeIPDomain6} {
			if tx.Bucket(bucketName) == nil {
				continue
			}
			found = true
			if err := tx.DeleteBucket(bucketName); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || !found {
		db.Close()
		return err
	}
	compacted := path + ".compact"
	_ = os.Remove(compacted)
	dst, err := bbolt.Open(compacted, 0o666, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		db.Close()
		return err
	}
	err = bbolt.Compact(dst, db, 0)
	db.Close()
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(compacted)
		return err
	}
	return os.Rename(compacted, path)
}

func (c *CacheFile) FakeIPStoreAsync(address netip.Addr, domain string, logger logger.Logger) {
	// neko: the ordered writer, as FakeIPStoreAsyncWithMetadata
	c.FakeIPStoreAsyncWithMetadata(address, domain, nil, logger)
}

func (c *CacheFile) FakeIPLoad(address netip.Addr) (string, bool) {
	c.saveFakeIPAccess.RLock()
	cachedDomain, cached := c.saveDomain[address]
	c.saveFakeIPAccess.RUnlock()
	if cached {
		return cachedDomain, true
	}
	var domain string
	_ = c.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		domain = string(bucket.Get(address.AsSlice()))
		return nil
	})
	return domain, domain != ""
}

func (c *CacheFile) FakeIPLoadDomain(domain string, isIPv6 bool) (netip.Addr, bool) {
	var (
		cachedAddress netip.Addr
		cached        bool
	)
	c.saveFakeIPAccess.RLock()
	if !isIPv6 {
		cachedAddress, cached = c.saveAddress4[domain]
	} else {
		cachedAddress, cached = c.saveAddress6[domain]
	}
	c.saveFakeIPAccess.RUnlock()
	if cached {
		return cachedAddress, true
	}
	var address netip.Addr
	_ = c.view(func(tx *bbolt.Tx) error {
		var bucket *bbolt.Bucket
		if isIPv6 {
			bucket = tx.Bucket(bucketFakeIPDomain6)
		} else {
			bucket = tx.Bucket(bucketFakeIPDomain4)
		}
		if bucket == nil {
			return nil
		}
		address = M.AddrFromIP(bucket.Get([]byte(domain)))
		return nil
	})
	return address, address.IsValid()
}

func (c *CacheFile) FakeIPReset() error {
	return c.batch(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketFakeIP, bucketFakeIPDomain4, bucketFakeIPDomain6} {
			if tx.Bucket(bucketName) == nil {
				continue
			}
			err := tx.DeleteBucket(bucketName)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
