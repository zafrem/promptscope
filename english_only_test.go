package promptscope

import (
	"encoding/base64"
	"errors"
	"testing"
)

func englishOnlyEngine(t *testing.T) Engine {
	t.Helper()
	rs, err := MergeRules(BaselineRules(), EnglishOnlyRules())
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{}, rs)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func ruleIDs(ms []Match) map[string]bool {
	ids := map[string]bool{}
	for _, m := range ms {
		ids[m.RuleID] = true
	}
	return ids
}

func TestEnglishOnlyScripts(t *testing.T) {
	e := englishOnlyEngine(t)
	cases := []struct {
		name, text string
		want, not  []string
		safe       bool
	}{
		{"korean", "안녕하세요 도와주세요", []string{"SCR-001"}, []string{"SCR-002", "SCR-003"}, false},
		{"japanese", "これはテストです", []string{"SCR-002"}, []string{"SCR-001", "SCR-003"}, false},
		{"japanese with kanji", "日本語のテスト", []string{"SCR-002", "SCR-003"}, []string{"SCR-001"}, false},
		{"pure kanji", "中文", []string{"SCR-003"}, []string{"SCR-001", "SCR-002", "SCR-004", "SCR-005"}, false},
		{"simplified", "我们这是一个简单的测试", []string{"SCR-003", "SCR-004"}, []string{"SCR-005"}, false},
		{"traditional", "我們這是一個簡單的測試", []string{"SCR-003", "SCR-005"}, []string{"SCR-004"}, false},
		{"half-width katakana via NFKC", "ﾃｽﾄ", []string{"SCR-002"}, nil, false},
		{"english", "What is the capital of France?", nil, []string{"SCR-001", "SCR-002", "SCR-003"}, true},
		{"accented latin", "café résumé naïve", nil, []string{"SCR-001", "SCR-002", "SCR-003"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := e.ScanPrompt(c.text)
			if err != nil {
				t.Fatal(err)
			}
			if r.IsSafe != c.safe {
				t.Errorf("IsSafe = %v (score %v), want %v", r.IsSafe, r.RiskScore, c.safe)
			}
			ids := ruleIDs(r.Matches)
			for _, id := range c.want {
				if !ids[id] {
					t.Errorf("missing %s in %v", id, r.Matches)
				}
			}
			for _, id := range c.not {
				if ids[id] {
					t.Errorf("unexpected %s in %v", id, r.Matches)
				}
			}
		})
	}
}

func TestEnglishOnlyOffsetsCoverRun(t *testing.T) {
	e := englishOnlyEngine(t)
	text := "say 안녕하세요 now"
	r, err := e.ScanPrompt(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.Matches {
		if m.RuleID == "SCR-001" {
			if got := text[m.Start:m.End]; got != "안녕하세요" {
				t.Errorf("span = %q", got)
			}
			return
		}
	}
	t.Fatal("no SCR-001 match")
}

func TestEnglishOnlyThroughBase64(t *testing.T) {
	e := englishOnlyEngine(t)
	blob := base64.StdEncoding.EncodeToString([]byte("안녕하세요 도와주세요 부탁합니다"))
	r, err := e.ScanPrompt("data: " + blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.Matches {
		if m.RuleID == "SCR-001" && len(m.Via) > 0 && m.Via[0] == "base64" {
			return
		}
	}
	t.Errorf("no SCR-001 via base64: %+v", r.Matches)
}

func TestBaselineAloneIgnoresScripts(t *testing.T) {
	e, err := New(Config{}, BaselineRules())
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.ScanPrompt("안녕하세요 これはテスト 中文")
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsSafe || len(r.Matches) != 0 {
		t.Errorf("baseline flagged non-English text: %+v", r)
	}
}

func TestEnglishOnlyPromptOnly(t *testing.T) {
	e := englishOnlyEngine(t)
	s, err := e.SanitizeContext("한국어 문서입니다")
	if err != nil {
		t.Fatal(err)
	}
	if s.HasInjection || s.SanitizedText != "한국어 문서입니다" {
		t.Errorf("context was altered: %+v", s)
	}
	o, err := e.ScanOutput("한국어 응답")
	if err != nil {
		t.Fatal(err)
	}
	if o.IsLeaked || len(o.Matches) != 0 {
		t.Errorf("output flagged: %+v", o)
	}
}

func TestBuiltinPack(t *testing.T) {
	for _, n := range BuiltinPackNames {
		rs, err := BuiltinPack(n)
		if err != nil || rs.Len() == 0 {
			t.Errorf("BuiltinPack(%q) = %v, %v", n, rs, err)
		}
	}
	if _, err := BuiltinPack("nope"); !errors.Is(err, ErrInvalidRules) {
		t.Errorf("unknown pack error = %v", err)
	}
	if EnglishOnlyRules().Pack() != "english-only" {
		t.Error("pack name")
	}
}
