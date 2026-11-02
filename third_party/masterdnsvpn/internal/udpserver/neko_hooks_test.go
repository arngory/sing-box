package udpserver

import (
	"testing"

	"masterdnsvpn-go/internal/config"
)

func TestNekoDNSResolverHook(t *testing.T) {
	s := New(config.ServerConfig{}, nil, nil)
	s.SetDNSResolver(func(query []byte) ([]byte, error) { return []byte("refused"), nil })
	answer, err := s.resolveDNSUpstream([]byte{1})
	if err != nil || string(answer) != "refused" {
		t.Fatalf("%q %v", answer, err)
	}
}
