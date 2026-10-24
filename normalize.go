package promptscope

import (
	"sort"
	"strings"
	"unicode"
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

// cyrillicLookalike maps Cyrillic letters that render like a Latin letter to that letter. Letters that only
// resemble a Latin one in small caps or italics (в, н, т, к, м) are left out of the lowercase half.
var cyrillicLookalike = map[rune]rune{
	'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l', 'ё': 'e', 'ү': 'y',
	'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
	'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'Ё': 'E', 'Ү': 'Y',
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsMark(r) }

// foldHomoglyphs replaces look-alike Cyrillic letters with their Latin twins, but only inside words that also
// contain a Latin letter. A word written entirely in Cyrillic is ordinary Russian, Ukrainian or similar and is
// left alone, which also means a word made only of look-alikes is not folded. The returned map is nil when
// nothing changed.
func foldHomoglyphs(s string) (string, offsetMap) {
	has := false
	for _, r := range s {
		if _, ok := cyrillicLookalike[r]; ok {
			has = true
			break
		}
	}
	if !has {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	var m offsetMap
	changed := false
	idStart, idOut := -1, 0
	flushRun := func(end int) {
		if idStart >= 0 {
			m = append(m, piece{idOut, b.Len(), idStart, end, true})
			idStart = -1
		}
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isWordRune(r) {
			if idStart < 0 {
				idStart, idOut = i, b.Len()
			}
			b.WriteString(s[i : i+size])
			i += size
			continue
		}
		j := i
		latin, fold := false, false
		for j < len(s) {
			wr, ws := utf8.DecodeRuneInString(s[j:])
			if !isWordRune(wr) {
				break
			}
			if unicode.Is(unicode.Latin, wr) {
				latin = true
			} else if _, ok := cyrillicLookalike[wr]; ok {
				fold = true
			}
			j += ws
		}
		if !(latin && fold) {
			if idStart < 0 {
				idStart, idOut = i, b.Len()
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		for k := i; k < j; {
			wr, ws := utf8.DecodeRuneInString(s[k:])
			if to, ok := cyrillicLookalike[wr]; ok {
				flushRun(k)
				out := b.Len()
				b.WriteRune(to)
				m = append(m, piece{out, b.Len(), k, k + ws, false})
				changed = true
			} else {
				if idStart < 0 {
					idStart, idOut = k, b.Len()
				}
				b.WriteString(s[k : k+ws])
			}
			k += ws
		}
		i = j
	}
	flushRun(len(s))
	if !changed {
		return s, nil
	}
	return b.String(), m
}

// normalized is text after the normalization stage together with the means to
// map ranges of it back to the original input.
type normalized struct {
	text string
	maps []offsetMap // applied in order; resolved in reverse
	// preFold is the text before look-alike letters were folded; the last map in maps is the fold when
	// folded is set.
	preFold string
	folded  bool
}

// normalize runs the stage: strip invisibles, NFKC, then fold look-alike
// letters to Latin. ASCII input is returned untouched without allocation.
func normalize(s string) normalized {
	n := normalized{text: s, preFold: s}
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
	n.preFold = n.text
	n.text, m = foldHomoglyphs(n.text)
	if m != nil {
		n.maps = append(n.maps, m)
		n.folded = true
	}
	return n
}

// resolvePreFold maps [s, e) of preFold to a range of the original input.
func (n normalized) resolvePreFold(s, e int) (int, int) {
	maps := n.maps
	if n.folded {
		maps = maps[:len(maps)-1]
	}
	for i := len(maps) - 1; i >= 0; i-- {
		s, e = maps[i].resolve(s, e)
	}
	return s, e
}

// resolve maps [s, e) of the normalized text to a range of the original input.
func (n normalized) resolve(s, e int) (int, int) {
	for i := len(n.maps) - 1; i >= 0; i-- {
		s, e = n.maps[i].resolve(s, e)
	}
	return s, e
}
