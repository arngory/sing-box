# tcpdesync

Cuts the first write of a TCP connection like tpws and ByeDPI do (design: arngory/niko `docs/design/dpi.md` §5.1,
release 1.67). Options: route rule `tcp_desync`, TLS outbound `desync`.

```json
"tcp_desync": {"split": [{"at": "1", "mode": "split"}, {"at": "sni+1", "mode": "disoob"}], "tlsrec": ["sni+2"], "oob_byte": "a"}
```

- Markers: a number (negative counts from the end, `-1` is the last byte), `host`/`sni`, `endhost`, `midhost`,
  `sld`, `midsld`, `endsld`, `sniext`, each with `+N`/`-N`. A cut at position p goes before byte p. Positions are
  counted on the whole first write (the assembled ClientHello record, header included); out of range or absent
  markers give no cut; the cuts are sorted and duplicates dropped, as in zapret. `tlsrec` uses the same positions
  and runs before the segment cuts. `midhost` (ByeDPI's `+sm`) and `endsld` are extra; zapret's `method` is not
  supported.
- A split's mode is how the part that ends at its marker is sent; the rest goes out normally.
- Only a TLS ClientHello record or a plain HTTP request is cut. Anything else passes untouched, absolute markers
  included (zapret's `--dpi-desync-any-protocol` is not there).

## How it sends (Linux, Android)

- A piece is its own segment because TCP_NODELAY is on and the next piece is written only once
  `tcpi_notsent_bytes == 0` (polled, at most 100 ms). No ACK is awaited and there is no 500 ms sleep.
- On kernels without `tcpi_notsent_bytes` (before 4.6; detected by `tcpi_min_rtt == 0`) the sender waits for the
  ACK of each piece instead (at most 500 ms), or, for a low-TTL piece, for the count of unacknowledged segments to
  grow (at most 100 ms).
- `disorder`/`disoob`: TTL (or IPv6 hop limit) 1 for the piece, restored as soon as the piece has left the queue,
  so the kernel's retransmission carries the normal TTL. The ACK is awaited once, after the whole first write, until
  everything is acknowledged (at most 2 s): waiting for the ACK of the low-TTL piece before sending the next one
  would let the retransmission go first and undo the disorder.
- `oob`/`disoob`: the piece and the OOB byte go in one `send(MSG_OOB)` through `SyscallConn`, as ByeDPI does.
- The first write waits for the rest of a ClientHello record (at most 16 KiB + 5 bytes and 200 ms); after that it
  goes out unchanged with one debug log line.

`Capabilities()` probes IP_TTL on a TCP socket, MSG_OOB (a receiver without SO_OOBINLINE must not see the byte) and
`tcpi_notsent_bytes` on a 127.0.0.1 connection, once. It probes IPv4 only.

## Gaps

- Other platforms: pieces are separate writes with no queue check; `disorder` and `oob` are sent as `split`
  without the OOB byte, with one warning. `Capabilities()` reports nothing there.
- More than one `oob`/`disoob` cut in one first write is unreliable: a Linux receiver keeps only the latest urgent
  byte out of the stream if the earlier one was not read yet.
- A partial `send(MSG_OOB)` would mark a stream byte as urgent; it is reported as an error instead. It does not
  happen on a fresh socket.
- Route rule: applies only when writes reach a `*net.TCPConn` unchanged (`N.UnwrapWriter`). A proxied connection
  gets a warning and no cuts; so does a TCP Fast Open connection, whose socket does not exist before the first
  write. A SOCKS or HTTP CONNECT outbound hands back the socket itself after its handshake, so it is cut: the bytes
  on that socket are the client's bytes.
- TLS outbounds: without a TCP socket under the connection (a detour through another proxy) only `tlsrec` applies.
  QUIC-based outbounds (Hysteria2, TUIC) do not use it; naive and the Apple/Windows engines reject it.
- Loopback cannot drop a TTL=1 packet; the disorder test drops it with iptables on INPUT in a network namespace of
  its own (root only), after it has left the socket, as a first hop would.
- `fake`, `auto` and `use` are rejected until 1.68.
