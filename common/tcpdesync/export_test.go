package tcpdesync

// SetTestHooks sets the TTL and plan hooks until the returned function is called.
func SetTestHooks(ttl func(int), pieces func([]Piece)) func() {
	testHookTTL, testHookPieces = ttl, pieces
	return func() { testHookTTL, testHookPieces = nil, nil }
}
