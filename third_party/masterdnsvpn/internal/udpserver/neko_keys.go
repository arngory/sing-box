package udpserver

import (
	"errors"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/mdseal"
	"masterdnsvpn-go/internal/security"
)

// neko: the service key's rotation (raycontrol docs/spec/masterdns-key-rotation.md §3). The server holds the current
// key and, for a grace, the previous one: a query opens with the first whose AES-GCM tag holds, and that key is the
// query's. A session keeps the key its SESSION_INIT opened with: its queries open, and its answers are sealed, with
// that key alone; a query to it opened with another key is not its. A key taken out of the list closes its sessions
// at once.

// maxServiceKeys is the current key and the previous one.
const maxServiceKeys = 2

// serviceKey is one of the service's keys: the codec that opens its queries, the seal keys of its answers (nil when
// answers go open). Never changed once made: a session holds it by its pointer.
type serviceKey struct {
	text  string
	codec *security.Codec
	seal  *mdseal.Keys
}

type serviceKeys []*serviceKey

func (keys serviceKeys) byText(text string) *serviceKey {
	for _, key := range keys {
		if key.text != "" && key.text == text {
			return key
		}
	}
	return nil
}

// currentKeys is the service's keys, the current first.
func (s *Server) currentKeys() serviceKeys {
	if keys := s.keys.Load(); keys != nil {
		return *keys
	}
	return nil
}

// firstCodec is the current key's codec (its method is the service's).
func (s *Server) firstCodec() *security.Codec {
	if keys := s.currentKeys(); len(keys) > 0 {
		return keys[0].codec
	}
	return nil
}

// SetKeys replaces the service's keys, the current first and the previous after it, as niko-server reads them from
// the key file. A key kept keeps its sessions; the sessions of a key no longer listed close now (the key may be in
// other hands). More than one key needs AES-GCM (methods 3-5): under the others no tag tells which key a query is in.
func (s *Server) SetKeys(texts []string) error {
	if len(texts) == 0 || len(texts) > maxServiceKeys {
		return fmt.Errorf("masterdnsvpn: %d keys (1 or %d: the current and the previous)", len(texts), maxServiceKeys)
	}
	method := s.cfg.DataEncryptionMethod
	if method == 0 {
		return errors.New("masterdnsvpn: DATA_ENCRYPTION_METHOD 0 has no key")
	}
	if len(texts) > 1 && method < 3 {
		return errors.New("masterdnsvpn: a previous key needs DATA_ENCRYPTION_METHOD 3-5 (AES-GCM)")
	}
	for _, text := range texts {
		if want := KeyLength(method); len(text) != want {
			return fmt.Errorf("masterdnsvpn: the key for method %d must be %d characters, one has %d", method, want, len(text))
		}
	}
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	old := s.currentKeys()
	next := make(serviceKeys, 0, len(texts))
	for i, text := range texts {
		if text == "" {
			return errors.New("masterdnsvpn: an empty key")
		}
		for _, earlier := range texts[:i] {
			if earlier == text {
				return errors.New("masterdnsvpn: the same key twice")
			}
		}
		if key := old.byText(text); key != nil {
			next = append(next, key)
			continue
		}
		key, err := s.newServiceKey(text)
		if err != nil {
			return err
		}
		next = append(next, key)
	}
	s.keys.Store(&next)

	kept := make(map[*serviceKey]bool, len(next))
	for _, key := range next {
		kept[key] = true
	}
	now := time.Now()
	for _, id := range s.sessions.withKeyNotIn(kept) {
		record, ok := s.sessions.Close(id, now, s.cfg.ClosedSessionRetention())
		if !ok {
			continue
		}
		s.cleanupClosedSession(id, record)
		if s.log != nil {
			s.log.Infof("\U0001F511 <yellow>Session Closed, its key taken out, Session: <cyan>%d</cyan></yellow>", id)
		}
	}
	return nil
}

// KeyLength is the length of a key for method (1-5), in characters, as the key file holds it.
func KeyLength(method int) int {
	switch method {
	case 3:
		return 16
	case 4:
		return 24
	}
	return 32
}

func (s *Server) newServiceKey(text string) (*serviceKey, error) {
	codec, err := security.NewCodecFromConfig(s.cfg, text)
	if err != nil {
		return nil, fmt.Errorf("masterdnsvpn: %w", err)
	}
	key := &serviceKey{text: text, codec: codec}
	if s.sealMode != sealOff {
		if key.seal, err = mdseal.NewKeys(text); err != nil {
			return nil, err
		}
	}
	return key, nil
}
