package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/url"
)

func (c *Core) _applyOption(opt SetupOption) (err error) {
	switch v := opt.(type) {
	case Peer:
		u, err := url.Parse(v.URI)
		if err != nil {
			return fmt.Errorf("unable to parse peering URI: %w", err)
		}
		err = c.links.add(u, v.SourceInterface, linkTypePersistent)
		switch err {
		case ErrLinkAlreadyConfigured:
			// Don't return this error, otherwise we'll panic at startup
			// if there are multiple of the same peer configured
			return nil
		default:
			return err
		}
	case ListenAddress:
		c.config._listeners[v] = struct{}{}
	case PeerFilter:
		c.config.peerFilter = v
	case NodeInfo:
		c.config.nodeinfo = v
	case NodeInfoPrivacy:
		c.config.nodeinfoPrivacy = v
	case AllowedPublicKey:
		pk := [32]byte{}
		copy(pk[:], v)
		c.config._allowedPublicKeys[pk] = struct{}{}
	case GroupPassword:
		c.config.groupPassword = string(v)
	case LinkDialer:
		c.config.linkDialer = v
	}
	return
}

type SetupOption interface {
	isSetupOption()
}

type ListenAddress string
type Peer struct {
	URI             string
	SourceInterface string
}
type NodeInfo map[string]interface{}
type NodeInfoPrivacy bool
type AllowedPublicKey ed25519.PublicKey
type PeerFilter func(net.IP) bool
type GroupPassword string

// LinkDialer opens the outgoing peering connections when set (neko addition): a program
// embedding the core routes them through its own dialer, for example to keep them out of
// a VPN it provides. Pass it before any Peer. Link-local peers keep the plain dialer.
type LinkDialer struct {
	DialContext  func(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket func(ctx context.Context, network, address string) (net.PacketConn, error)
}

func (a ListenAddress) isSetupOption()    {}
func (a Peer) isSetupOption()             {}
func (a NodeInfo) isSetupOption()         {}
func (a NodeInfoPrivacy) isSetupOption()  {}
func (a AllowedPublicKey) isSetupOption() {}
func (a PeerFilter) isSetupOption()       {}
func (a GroupPassword) isSetupOption()    {}
func (a LinkDialer) isSetupOption()       {}
