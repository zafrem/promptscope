package promptscope

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zafrem/promptscope/internal/norm"
)

// piece maps the output range [outStart, outEnd) of a transform to the input
// range [inStart, inEnd). In an identity piece the two ranges have equal
// length and map byte for byte; otherwise the whole output range maps to the
// whole input range.
type piece struct {
	outStart, outEnd int
	inStart, inEnd   int
	identity         bool
}

// offsetMap relates the output of one transform back to its input. Pieces are
// sorted by outStart and cover the whole output.
type offsetMap []piece

func (m offsetMap) find(o int) piece {
	i := sort.Search(len(m), func(i int) bool { return m[i].outEnd > o })
	if i == len(m) {
		i = len(m) - 1
	}
	return m[i]
}

// resolve maps the output range [s, e) to an input range.
func (m offsetMap) resolve(s, e int) (int, int) {
	if len(m) == 0 {
		return s, e
	}
	ps := m.find(s)
	pe := m.find(e - 1)
	in0 := ps.inStart
	if ps.identity {
		in0 += s - ps.outStart
	}
	in1 := pe.inEnd
	if pe.identity {
		in1 = pe.inStart + (e - pe.outStart)
	}
	return in0, in1
}

// isASCII reports whether s is pure ASCII. Every invisible character and every
// character NFKC would change lies outside ASCII, so such text needs no
// normalization.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// isInvisible reports whether r is a zero-width, bidirectional control or
// other format character that renders as nothing (FR-1.3, FR-2.1).
func isInvisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, // ZWSP, ZWNJ, ZWJ, LRM, RLM
		r >= 0x202A && r <= 0x202E, // bidi embeddings and overrides
		r >= 0x2060 && r <= 0x2064, // word joiner, invisible operators
		r >= 0x2066 && r <= 0x2069, // bidi isolates
		r == 0xFEFF,                // BOM / ZWNBSP
		r == 0x00AD,                // soft hyphen
		r == 0x180E:                // Mongolian vowel separator
		return true
	}
	return false
}

// stripInvisible removes invisible characters. The returned map is nil when
// nothing changed.
func stripInvisible(s string) (string, offsetMap) {
	first := strings.IndexFunc(s, isInvisible)
	if first < 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	var m offsetMap
	runStart := 0 // start of the current kept run, in input bytes
	flush := func(end int) {
		if end > runStart {
			out := b.Len()
			b.WriteString(s[runStart:end])
			m = append(m, piece{out, b.Len(), runStart, end, true})
		}
	}
	for i, r := range s {
		if isInvisible(r) {
			flush(i)
			runStart = i + utf8.RuneLen(r)
		}
	}
	flush(len(s))
	return b.String(), m
}

// foldNFKC applies Unicode normalization form NFKC. It works one normalization
// segment at a time so that every output byte can be traced to its input
// segment. The returned map is nil when nothing changed.
func foldNFKC(s string) (string, offsetMap) {
	if norm.NFKC.IsNormalString(s) {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	var m offsetMap
	idStart, idOut := -1, 0 // pending identity run: input start, output start
	flushRun := func(end int) {
		if idStart >= 0 {
			m = append(m, piece{idOut, b.Len(), idStart, end, true})
			idStart = -1
		}
	}
	for i := 0; i < len(s); {
		n := norm.NFKC.NextBoundaryInString(s[i:], true)
		if n <= 0 {
			n = len(s) - i
		}
		seg := s[i : i+n]
		if norm.NFKC.IsNormalString(seg) {
			if idStart < 0 {
				idStart, idOut = i, b.Len()
			}
			b.WriteString(seg)
		} else {
			flushRun(i)
			out := b.Len()
			b.WriteString(norm.NFKC.String(seg))
			m = append(m, piece{out, b.Len(), i, i + n, false})
		}
		i += n
	}
	flushRun(len(s))
	return b.String(), m
}

// normalized is text after the normalization stage together with the means to
// map ranges of it back to the original input.
type normalized struct {
	text string
	maps []offsetMap // applied in order; resolved in reverse
}

// normalize runs the stage: strip invisibles, then NFKC. ASCII input is
// returned untouched without allocation.
func normalize(s string) normalized {
	n := normalized{text: s}
	if isASCII(s) {
		return n
	}
	var m offsetMap
	n.text, m = stripInvisible(n.text)
	if m != nil {
		n.maps = append(n.maps, m)
	}
	n.text, m = foldNFKC(n.text)
	if m != nil {
		n.maps = append(n.maps, m)
	}
	return n
}

// resolve maps [s, e) of the normalized text to a range of the original input.
func (n normalized) resolve(s, e int) (int, int) {
	for i := len(n.maps) - 1; i >= 0; i-- {
		s, e = n.maps[i].resolve(s, e)
	}
	return s, e
}
