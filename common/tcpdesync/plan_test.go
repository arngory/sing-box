package tcpdesync_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/tcpdesync"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestParseMarker(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]tcpdesync.Marker{
		"1":         {Base: tcpdesync.BaseAbsolute, Offset: 1},
		"-10":       {Base: tcpdesync.BaseAbsolute, Offset: -10},
		"sni":       {Base: tcpdesync.BaseHost},
		"host+1":    {Base: tcpdesync.BaseHost, Offset: 1},
		" SNI+2 ":   {Base: tcpdesync.BaseHost, Offset: 2},
		"endhost-2": {Base: tcpdesync.BaseEndHost, Offset: -2},
		"midhost":   {Base: tcpdesync.BaseMidHost},
		"sld":       {Base: tcpdesync.BaseSLD},
		"midsld+1":  {Base: tcpdesync.BaseMidSLD, Offset: 1},
		"endsld":    {Base: tcpdesync.BaseEndSLD},
		"sniext+1":  {Base: tcpdesync.BaseSNIExt, Offset: 1},
	} {
		marker, err := tcpdesync.ParseMarker(text)
		require.NoError(t, err, text)
		require.Equal(t, want, marker, text)
		again, err := tcpdesync.ParseMarker(marker.String())
		require.NoError(t, err)
		require.Equal(t, marker, again)
	}
	for _, text := range []string{"", "sni+", "sni+x", "sni++1", "+1x", "foo", "method", "sni+1+2", "99999999", "1.5"} {
		_, err := tcpdesync.ParseMarker(text)
		require.Error(t, err, text)
	}
}

func TestParseOptions(t *testing.T) {
	t.Parallel()
	strategy, err := tcpdesync.Parse(nil)
	require.NoError(t, err)
	require.Nil(t, strategy)

	strategy, err = tcpdesync.Parse(&option.TCPDesyncOptions{
		Split:  []option.TCPDesyncSplitOptions{{At: "1", Mode: "split"}, {At: "sni+1", Mode: "disoob"}, {At: "midsld"}},
		TLSRec: []string{"sni+2"},
	})
	require.NoError(t, err)
	require.Equal(t, byte('a'), strategy.OOBByte)
	require.Equal(t, []tcpdesync.Split{
		{At: tcpdesync.Marker{Offset: 1}, Mode: tcpdesync.ModeSplit},
		{At: tcpdesync.Marker{Base: tcpdesync.BaseHost, Offset: 1}, Mode: tcpdesync.ModeDisOOB},
		{At: tcpdesync.Marker{Base: tcpdesync.BaseMidSLD}, Mode: tcpdesync.ModeSplit},
	}, strategy.Splits)
	require.Equal(t, "split=1:split,host+1:disoob,midsld:split tlsrec=host+2 oob_byte='a'", strategy.String())

	for name, test := range map[string]struct {
		options option.TCPDesyncOptions
		message string
	}{
		"empty":       {option.TCPDesyncOptions{}, "nothing to do"},
		"bad marker":  {option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "sni+"}}}, "bad marker offset"},
		"bad tlsrec":  {option.TCPDesyncOptions{TLSRec: []string{"nowhere"}}, "unknown marker"},
		"bad mode":    {option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "multisplit"}}}, "unknown mode"},
		"fake mode":   {option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "fake"}}}, "not supported until 1.68"},
		"fake":        {option.TCPDesyncOptions{TLSRec: []string{"sni"}, Fake: []byte(`{"ttl":5}`)}, "fake is not supported until 1.68"},
		"auto":        {option.TCPDesyncOptions{TLSRec: []string{"sni"}, Auto: []byte(`{}`)}, "auto is not supported until 1.68"},
		"use":         {option.TCPDesyncOptions{Use: "auto"}, "use is not supported until 1.68"},
		"oob_byte":    {option.TCPDesyncOptions{TLSRec: []string{"sni"}, OOBByte: "ab"}, "oob_byte must be one byte"},
		"no at":       {option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{Mode: "oob"}}}, "empty marker"},
		"split index": {option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1"}, {At: "x"}}}, "split[1]"},
	} {
		_, err = tcpdesync.Parse(&test.options)
		require.ErrorContains(t, err, test.message, name)
		require.True(t, strings.HasPrefix(err.Error(), "tcp_desync: "), err.Error())
	}

	_, err = tcpdesync.ParseOutbound(&option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1"}, {At: "sni+1", Mode: "oob"}}, TLSRec: []string{"sni"}})
	require.NoError(t, err)
	for _, mode := range []string{"disorder", "disoob"} {
		_, err = tcpdesync.ParseOutbound(&option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: mode}}})
		require.ErrorContains(t, err, "not allowed for outbound handshakes", mode)
	}
	_, err = tcpdesync.ParseOutbound(&option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "fake"}}})
	require.ErrorContains(t, err, "tls.desync: split[0]: mode fake is not supported until 1.68")
}

func TestOptionsJSON(t *testing.T) {
	t.Parallel()
	content := `{"split":[{"at":"1","mode":"split"},{"at":"sni+1","mode":"disoob"}],"tlsrec":["sni+2"],"oob_byte":"a"}`
	options, err := json.UnmarshalExtendedContext[option.TCPDesyncOptions](context.Background(), []byte(content))
	require.NoError(t, err)
	strategy, err := tcpdesync.Parse(&options)
	require.NoError(t, err)
	require.Len(t, strategy.Splits, 2)
	require.Equal(t, tcpdesync.ModeDisOOB, strategy.Splits[1].Mode)
	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.Equal(t, `{"split":[{"at":"1","mode":"split"},{"at":"sni+1","mode":"disoob"}],"tlsrec":"sni+2","oob_byte":"a"}`, string(encoded))

	// a single tlsrec marker may be a string; fake is kept for the error at load
	options, err = json.UnmarshalExtendedContext[option.TCPDesyncOptions](context.Background(), []byte(`{"tlsrec":"sni+1","fake":{"ttl":5}}`))
	require.NoError(t, err)
	require.Equal(t, []string{"sni+1"}, []string(options.TLSRec))
	_, err = tcpdesync.Parse(&options)
	require.ErrorContains(t, err, "tcp_desync: fake is not supported until 1.68")
}

func TestLocate(t *testing.T) {
	t.Parallel()
	for _, fixture := range helloFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			hello := fixture.hello
			positions := tcpdesync.Locate(hello)
			require.Equal(t, tcpdesync.ProtocolTLS, positions.Protocol)
			require.Equal(t, len(hello), positions.RecordEnd)
			if fixture.sni == "" {
				require.Equal(t, -1, positions.Host)
				for _, text := range []string{"sni", "endhost", "midhost", "sld", "midsld", "endsld", "sniext"} {
					marker, err := tcpdesync.ParseMarker(text)
					require.NoError(t, err)
					_, ok := marker.Resolve(hello, positions)
					require.False(t, ok, text)
				}
				return
			}
			require.Equal(t, fixture.sni, string(hello[positions.Host:positions.EndHost]))
			// sniext: the data of the extension of type 0, whose length is the list length + 2
			require.Equal(t, []byte{0, 0}, hello[positions.SNIExt-4:positions.SNIExt-2])
			require.Equal(t, int(binary.BigEndian.Uint16(hello[positions.SNIExt-2:])), len(fixture.sni)+5)
			labels := strings.Split(fixture.sni, ".")
			sld := labels[len(labels)-2]
			sldStart := positions.Host + strings.LastIndex(fixture.sni, sld+".")
			for text, want := range map[string]int{
				"sni":      positions.Host,
				"host+1":   positions.Host + 1,
				"endhost":  positions.Host + len(fixture.sni),
				"midhost":  positions.Host + len(fixture.sni)/2,
				"sld":      sldStart,
				"midsld":   sldStart + len(sld)/2,
				"endsld-1": sldStart + len(sld) - 1,
				"sniext":   positions.SNIExt,
				"1":        1,
				"-1":       len(hello) - 1,
			} {
				marker, err := tcpdesync.ParseMarker(text)
				require.NoError(t, err)
				position, ok := marker.Resolve(hello, positions)
				require.True(t, ok, text)
				require.Equal(t, want, position, text)
			}
			for _, text := range []string{"0", "-9999", "9999", "endhost+9999"} {
				marker, err := tcpdesync.ParseMarker(text)
				require.NoError(t, err)
				_, ok := marker.Resolve(hello, positions)
				require.False(t, ok, text)
			}
		})
	}
}

func TestLocateHelloSizes(t *testing.T) {
	t.Parallel()
	fixtures := helloFixtures(t)
	for _, fixture := range fixtures {
		t.Log(fixture.name, len(fixture.hello), "bytes, key shares", keyShareGroups(t, fixture.hello))
	}
	const x25519MLKEM768 = 0x11ec
	require.Greater(t, len(fixtures[0].hello), 1700)
	require.Contains(t, keyShareGroups(t, fixtures[0].hello), uint16(x25519MLKEM768))
	require.Greater(t, len(fixtures[1].hello), 1700)
	require.Contains(t, keyShareGroups(t, fixtures[1].hello), uint16(x25519MLKEM768))
	require.Greater(t, len(fixtures[2].hello), 1400)
	require.Contains(t, keyShareGroups(t, fixtures[2].hello), uint16(x25519MLKEM768))
}

func TestLocateHTTP(t *testing.T) {
	t.Parallel()
	request := []byte("GET /watch HTTP/1.1\r\nUser-Agent: x\r\nhOsT:  www.youtube.com:8080\r\nAccept: */*\r\n\r\n")
	positions := tcpdesync.Locate(request)
	require.Equal(t, tcpdesync.ProtocolHTTP, positions.Protocol)
	require.Equal(t, "www.youtube.com", string(request[positions.Host:positions.EndHost]))
	marker, _ := tcpdesync.ParseMarker("midsld")
	position, ok := marker.Resolve(request, positions)
	require.True(t, ok)
	require.Equal(t, "tube.com:8080", string(request[position:positions.EndHost+5]))
	marker, _ = tcpdesync.ParseMarker("sniext")
	_, ok = marker.Resolve(request, positions)
	require.False(t, ok)

	positions = tcpdesync.Locate([]byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"))
	require.Equal(t, tcpdesync.ProtocolHTTP, positions.Protocol)
	require.Equal(t, -1, positions.Host)
	require.Equal(t, tcpdesync.ProtocolUnknown, tcpdesync.Locate([]byte("SSH-2.0-OpenSSH_9.6\r\n")).Protocol)
}

// records parses the TLS records of stream: their headers' first three bytes and their payloads.
func records(t *testing.T, stream []byte) ([][]byte, [][]byte) {
	t.Helper()
	var headers, payloads [][]byte
	for len(stream) > 0 {
		require.GreaterOrEqual(t, len(stream), 5)
		length := int(binary.BigEndian.Uint16(stream[3:5]))
		require.GreaterOrEqual(t, len(stream), 5+length)
		require.Greater(t, length, 0)
		headers = append(headers, stream[:3])
		payloads = append(payloads, stream[5:5+length])
		stream = stream[5+length:]
	}
	return headers, payloads
}

func mustStrategy(t *testing.T, options option.TCPDesyncOptions) *tcpdesync.Strategy {
	t.Helper()
	strategy, err := tcpdesync.Parse(&options)
	require.NoError(t, err)
	return strategy
}

func splits(pairs ...string) []option.TCPDesyncSplitOptions {
	var out []option.TCPDesyncSplitOptions
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, option.TCPDesyncSplitOptions{At: pairs[i], Mode: pairs[i+1]})
	}
	return out
}

func TestPlan(t *testing.T) {
	t.Parallel()
	strategies := []option.TCPDesyncOptions{
		{Split: splits("1", "split")},
		{Split: splits("1", "split", "sni+1", "disoob"), TLSRec: []string{"sni+2"}},
		{Split: splits("sni+1", "oob", "midsld", "disorder", "endhost", "split", "-10", "split"), OOBByte: "!"},
		{TLSRec: []string{"sni+1"}},
		{TLSRec: []string{"1", "sniext", "midsld", "midsld", "-1"}, Split: splits("midsld", "split", "sniext", "oob")},
		{Split: splits("endhost", "split", "1", "disorder", "endhost", "oob")},
		{Split: splits("sni", "split"), TLSRec: []string{"sni"}},
	}
	for _, fixture := range helloFixtures(t) {
		hello := fixture.hello
		for _, options := range strategies {
			strategy := mustStrategy(t, options)
			name := fixture.name + " " + strategy.String()
			pieces := strategy.Plan(hello)
			if fixture.sni == "" && len(options.TLSRec) > 0 && options.TLSRec[0] == "sni+1" {
				require.Nil(t, pieces, name)
				continue
			}
			if pieces == nil {
				continue
			}
			stream := tcpdesync.Stream(pieces)
			headers, payloads := records(t, stream)
			for _, header := range headers {
				require.Equal(t, hello[:3], header, name)
			}
			require.Equal(t, hello[5:], bytes.Join(payloads, nil), name)
			require.Equal(t, len(hello)+5*(len(payloads)-1), len(stream), name)
			var oob int
			for i, piece := range pieces {
				require.NotEmpty(t, piece.Data, name)
				if piece.Mode.OutOfBand() {
					oob++
					require.Equal(t, strategy.OOBByte, piece.OOB, name)
				}
				if i == len(pieces)-1 {
					require.Equal(t, tcpdesync.ModeSplit, piece.Mode, name)
				}
			}
		}
	}

	// the cuts, on the Chrome reference
	hello := chromeHello(t, "www.youtube.com")
	positions := tcpdesync.Locate(hello)
	pieces := mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split", "sni+1", "disoob")}).Plan(hello)
	require.Len(t, pieces, 3)
	require.Equal(t, hello[:1], pieces[0].Data)
	require.Equal(t, tcpdesync.ModeSplit, pieces[0].Mode)
	require.Equal(t, hello[1:positions.Host+1], pieces[1].Data)
	require.Equal(t, tcpdesync.ModeDisOOB, pieces[1].Mode)
	require.Equal(t, byte('a'), pieces[1].OOB)
	require.Equal(t, hello[positions.Host+1:], pieces[2].Data)

	// duplicates and order: ascending, the first listed mode wins
	pieces = mustStrategy(t, option.TCPDesyncOptions{Split: splits("sni", "oob", "5", "split", "host", "disorder")}).Plan(hello)
	require.Len(t, pieces, 3)
	require.Len(t, pieces[0].Data, 5)
	require.Equal(t, tcpdesync.ModeOOB, pieces[1].Mode)

	// tlsrec at the same marker as a cut: the new header starts the next piece
	pieces = mustStrategy(t, option.TCPDesyncOptions{Split: splits("sni", "split"), TLSRec: []string{"sni"}}).Plan(hello)
	require.Len(t, pieces, 2)
	require.Equal(t, hello[5:positions.Host], pieces[0].Data[5:])
	require.Equal(t, byte(22), pieces[1].Data[0])
	require.Equal(t, hello[positions.Host:], pieces[1].Data[5:])

	// not TLS or HTTP: untouched
	require.Nil(t, mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split")}).Plan([]byte("SSH-2.0-OpenSSH_9.6\r\n")))
	// a ClientHello record not whole: untouched
	require.Nil(t, mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split")}).Plan(hello[:100]))
	// HTTP
	request := []byte("GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n")
	pieces = mustStrategy(t, option.TCPDesyncOptions{Split: splits("host+1", "split"), TLSRec: []string{"sni"}}).Plan(request)
	require.Len(t, pieces, 2)
	require.Equal(t, "GET / HTTP/1.1\r\nHost: w", string(pieces[0].Data))
	require.Equal(t, request, tcpdesync.Stream(pieces))
}
