package promptscope

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// encoded is a candidate blob found in text and successfully decoded.
type encoded struct {
	span Span   // byte range of the blob in the text it was found in
	kind string // "base64", "hex" or "hex-escape"
	text string // decoded, printable UTF-8
}

func isB64(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '-' || c == '_'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// findEncoded locates encoded blobs of at least minLen bytes in s and decodes
// them. Blobs whose decoded form is not mostly printable text are dropped, so
// hashes, identifiers and binary data pass through unnoticed.
func findEncoded(s string, minLen int) []encoded {
	var out []encoded
	for i := 0; i < len(s); {
		if !isB64(s[i]) {
			i++
			continue
		}
		j := i
		allHex := true
		for j < len(s) && isB64(s[j]) {
			allHex = allHex && isHex(s[j])
			j++
		}
		for pad := 0; pad < 2 && j < len(s) && s[j] == '='; pad++ {
			j++
		}
		blob := s[i:j]
		if len(strings.TrimRight(blob, "=")) >= minLen {
			if dec, kind, ok := decodeBlob(blob, allHex); ok {
				out = append(out, encoded{Span{i, j}, kind, dec})
			}
		}
		i = j
	}
	if strings.Contains(s, `\x`) {
		out = append(out, findHexEscapes(s, minLen)...)
	}
	return out
}

func decodeBlob(blob string, allHex bool) (string, string, bool) {
	trimmed := strings.TrimRight(blob, "=")
	if allHex && len(blob) == len(trimmed) && len(trimmed)%2 == 0 {
		if b, err := hex.DecodeString(trimmed); err == nil && printable(b) {
			return string(b), "hex", true
		}
	}
	enc := base64.RawStdEncoding
	if strings.ContainsAny(trimmed, "-_") {
		enc = base64.RawURLEncoding
	}
	if len(trimmed)%4 == 1 {
		return "", "", false
	}
	if b, err := enc.DecodeString(trimmed); err == nil && printable(b) {
		return string(b), "base64", true
	}
	return "", "", false
}

// findHexEscapes finds runs of \xNN escape sequences of at least minLen/3
// escapes (a sequence is four bytes long but carries one byte of data).
func findHexEscapes(s string, minLen int) []encoded {
	minEsc := minLen / 3
	if minEsc < 4 {
		minEsc = 4
	}
	var out []encoded
	for i := 0; i+4 <= len(s); {
		if !(s[i] == '\\' && s[i+1] == 'x' && isHex(s[i+2]) && isHex(s[i+3])) {
			i++
			continue
		}
		j, n := i, 0
		var raw []byte
		for j+4 <= len(s) && s[j] == '\\' && s[j+1] == 'x' && isHex(s[j+2]) && isHex(s[j+3]) {
			b, _ := hex.DecodeString(s[j+2 : j+4])
			raw = append(raw, b[0])
			j += 4
			n++
		}
		if n >= minEsc && printable(raw) {
			out = append(out, encoded{Span{i, j}, "hex-escape", string(raw)})
		}
		i = j
	}
	return out
}

// printable reports whether b is UTF-8 text made almost entirely of letters,
// digits, punctuation and spaces, and contains at least a few letters.
func printable(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	total, ok, letters := 0, 0, 0
	for _, r := range string(b) {
		total++
		switch {
		case unicode.IsLetter(r):
			letters++
			ok++
		case unicode.IsDigit(r), unicode.IsPunct(r), unicode.IsSpace(r), unicode.IsSymbol(r):
			ok++
		}
	}
	return letters >= 4 && ok*10 >= total*9
}
