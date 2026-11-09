package gpg

import "testing"

func TestParseStatusLine(t *testing.T) {
	line, ok := ParseStatusLine("[GNUPG:] KEY_CREATED B BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72")

	if !ok || line.Keyword != "KEY_CREATED" || len(line.Args) != 2 || line.Args[1] != "BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72" {
		t.Errorf("got %+v, %v", line, ok)
	}
}

func TestParseStatusLineRejectsNonStatus(t *testing.T) {
	for _, in := range []string{"", "gpg: checking the trustdb", "[GNUPG:]", "[GNUPG:] ", " [GNUPG:] NEWSIG"} {
		if _, ok := ParseStatusLine(in); ok {
			t.Errorf("ParseStatusLine(%q) accepted", in)
		}
	}
}

func TestParseStatusSkipsNoise(t *testing.T) {
	stream := "[GNUPG:] NEWSIG\ngpg: Signature made ...\n[GNUPG:] GOODSIG 438F68FF5D06DB72 Test User\n[GNUPG:] VALIDSIG BB11 2026-11-09\n"

	statuses := Statuses(ParseStatus([]byte(stream)))

	if len(statuses) != 3 || !statuses.Has("GOODSIG") || statuses.Has("BADSIG") {
		t.Fatalf("statuses = %+v", statuses)
	}
	goodsig, _ := statuses.First("GOODSIG")
	if len(goodsig.Args) != 3 {
		t.Errorf("GOODSIG args = %q", goodsig.Args)
	}
}

func FuzzParseStatus(f *testing.F) {
	f.Add([]byte("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG A B\n"))
	f.Add([]byte("[GNUPG:] \n[GNUPG:]\t\x00\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, line := range ParseStatus(data) {
			if line.Keyword == "" {
				t.Fatal("empty keyword accepted")
			}
		}
	})
}
