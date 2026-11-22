package tcpdesync

import (
	"encoding/binary"
	"slices"
)

// Piece is one send of the first write.
type Piece struct {
	// Data are the stream bytes of the piece. The pieces' Data together are the first write, with the record
	// headers tlsrec added.
	Data []byte
	// Mode is how the piece is sent. The last piece is always ModeSplit: the rest, sent normally.
	Mode Mode
	// OOB is the byte sent with MSG_OOB right after Data, for the oob modes. It is not part of the stream.
	OOB byte
}

// Plan cuts the first write b by the strategy. It is a pure function of the strategy and b. nil means: send b as
// it is (not TLS or HTTP, or no marker resolved).
func (s *Strategy) Plan(b []byte) []Piece {
	positions := Locate(b)
	if positions.Protocol == ProtocolUnknown {
		return nil
	}
	stream := b
	var recordCuts []int
	if positions.Protocol == ProtocolTLS && len(s.TLSRec) > 0 {
		for _, marker := range s.TLSRec {
			position, ok := marker.Resolve(b, positions)
			if ok && position > recordHeaderLen && position < positions.RecordEnd {
				recordCuts = append(recordCuts, position)
			}
		}
		slices.Sort(recordCuts)
		recordCuts = slices.Compact(recordCuts)
		if len(recordCuts) > 0 {
			stream = splitRecord(b, positions.RecordEnd, recordCuts)
		}
	}
	type cut struct {
		position int
		mode     Mode
	}
	var cuts []cut
	for _, split := range s.Splits {
		position, ok := split.At.Resolve(b, positions)
		if !ok {
			continue
		}
		// a record header added at the same position goes after the cut, with the bytes it heads
		shift := 0
		for _, recordCut := range recordCuts {
			if recordCut < position {
				shift += recordHeaderLen
			}
		}
		cuts = append(cuts, cut{position + shift, split.Mode})
	}
	// zapret normalises the same way: ascending, duplicates dropped (the first one listed wins)
	slices.SortStableFunc(cuts, func(a, b cut) int { return a.position - b.position })
	cuts = slices.CompactFunc(cuts, func(a, b cut) bool { return a.position == b.position })
	if len(cuts) == 0 {
		if len(recordCuts) == 0 {
			return nil
		}
		return []Piece{{Data: stream}}
	}
	pieces := make([]Piece, 0, len(cuts)+1)
	previous := 0
	for _, c := range cuts {
		piece := Piece{Data: stream[previous:c.position], Mode: c.mode}
		if c.mode.OutOfBand() {
			piece.OOB = s.OOBByte
		}
		pieces = append(pieces, piece)
		previous = c.position
	}
	return append(pieces, Piece{Data: stream[previous:]})
}

// splitRecord cuts the record b[:recordEnd] into records at cuts (positions in b, inside the record payload); the
// bytes after the record follow unchanged.
func splitRecord(b []byte, recordEnd int, cuts []int) []byte {
	out := make([]byte, 0, len(b)+len(cuts)*recordHeaderLen)
	previous := recordHeaderLen
	for i := 0; i <= len(cuts); i++ {
		end := recordEnd
		if i < len(cuts) {
			end = cuts[i]
		}
		out = append(out, b[0], b[1], b[2])
		out = binary.BigEndian.AppendUint16(out, uint16(end-previous))
		out = append(out, b[previous:end]...)
		previous = end
	}
	return append(out, b[recordEnd:]...)
}

// Stream is what the server reads from the pieces: their Data together, without the OOB bytes.
func Stream(pieces []Piece) []byte {
	var out []byte
	for _, piece := range pieces {
		out = append(out, piece.Data...)
	}
	return out
}
