package dnstt

// Adapted from dnstt-client/dns.go (www.bamsoftware.com/git/dnstt.git, public domain):
// packets travel base32-encoded in the QNAME of TXT queries and come back in TXT answers.

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// random padding in every query, more in polls, so equal payloads do not repeat on the wire
	numPadding        = 3
	numPaddingForPoll = 8

	// polls when there is nothing to send, backing off up to maxPollDelay
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0

	// a response may make room for this many immediate polls
	pollLimit = 16
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsPacketConn carries the tunnel's packets over a DNS transport: queries go to the
// resolver, which forwards them to the authoritative tunnel server for domain.
type dnsPacketConn struct {
	clientID  turbotunnel.ClientID
	domain    dns.Name
	pollChan  chan struct{}
	transport net.PacketConn
	logger    logger.ContextLogger
	done      chan struct{}
	closeOnce sync.Once
	*turbotunnel.QueuePacketConn
}

func newDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, logger logger.ContextLogger) *dnsPacketConn {
	clientID := turbotunnel.NewClientID()
	c := &dnsPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}, pollLimit),
		transport:       transport,
		logger:          logger,
		done:            make(chan struct{}),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		err := c.recvLoop()
		if err != nil && !c.isClosed() {
			logger.Debug("dnstt: receive: ", err)
		}
		c.Close()
	}()
	go c.sendLoop(addr)
	return c
}

func (c *dnsPacketConn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *dnsPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.transport.Close()
		c.QueuePacketConn.Close()
	})
	return nil
}

// dnsResponsePayload extracts the tunnel payload of a response: a single TXT answer
// under the tunnel domain with NOERROR.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 || resp.Flags&0x000f != dns.RcodeNoError || len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]
	if _, ok := answer.Name.TrimSuffix(domain); !ok || answer.Type != dns.RRTypeTXT {
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}
	return payload
}

// nextPacket reads a length-prefixed packet from the response payload.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

func (c *dnsPacketConn) recvLoop() error {
	var buf [4096]byte
	for {
		n, addr, err := c.transport.ReadFrom(buf[:])
		if err != nil {
			return err
		}
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}
		r := bytes.NewReader(dnsResponsePayload(&resp, c.domain))
		received := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			received = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
		// data came back: poll again at once, the server may have more queued
		if received {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		size := min(len(p), n)
		result = append(result, p[:size])
		p = p[size:]
	}
	return result
}

// send encodes one packet (or an empty poll) as a TXT query for <base32>.<domain>.
func (c *dnsPacketConn) send(p []byte, addr net.Addr) error {
	if len(p) >= 224 {
		return errors.New("packet too long")
	}
	var decoded bytes.Buffer
	decoded.Write(c.clientID[:])
	n := numPadding
	if len(p) == 0 {
		n = numPaddingForPoll
	}
	decoded.WriteByte(byte(224 + n))
	io.CopyN(&decoded, rand.Reader, int64(n))
	if len(p) > 0 {
		decoded.WriteByte(byte(len(p)))
		decoded.Write(p)
	}
	encoded := make([]byte, base32Encoding.EncodedLen(decoded.Len()))
	base32Encoding.Encode(encoded, decoded.Bytes())
	labels := append(chunks(bytes.ToLower(encoded), 63), c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}
	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{{
			Name:  name,
			Type:  dns.RRTypeTXT,
			Class: dns.ClassIN,
		}},
		// EDNS(0) for responses up to 4096 bytes
		Additional: []dns.RR{{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		}},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	_, err = c.transport.WriteTo(buf, addr)
	return err
}

func (c *dnsPacketConn) sendLoop(addr net.Addr) {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
	outgoing := c.QueuePacketConn.OutgoingQueue(addr)
	for {
		var p []byte
		pollTimerExpired := false
		// prefer data over a poll
		select {
		case p = <-outgoing:
		default:
			select {
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			case <-c.done:
				return
			}
		}
		// any query also works as a poll
		if len(p) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
		}
		if pollTimerExpired {
			pollDelay = min(time.Duration(float64(pollDelay)*pollDelayMultiplier), maxPollDelay)
		} else {
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)
		if err := c.send(p, addr); err != nil {
			if c.isClosed() {
				return
			}
			c.logger.Debug("dnstt: send: ", err)
		}
	}
}
