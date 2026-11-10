package gpg

import (
	"strings"
	"testing"
)

func TestArgvInteractiveCommandOmitsBatchAndUsesCommandFD(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}
	command, err := GenRevokeCommand("ABCD", RevokeCompromised, "lost laptop")
	if err != nil {
		t.Fatal(err)
	}

	argv := strings.Join(runner.Argv(command), " ")

	want := "/usr/bin/gpg --no-tty --status-fd 3 --command-fd 4 --gen-revoke -- ABCD"
	if argv != want {
		t.Errorf("argv = %q, want %q", argv, want)
	}
	if answers := command.Answers(); len(answers) != 5 {
		t.Errorf("answers = %+v, want 5 entries", answers)
	}
}

func TestArgvOrdinaryCommandKeepsBatch(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	argv := strings.Join(runner.Argv(ImportCommand()), " ")

	want := "/usr/bin/gpg --batch --status-fd 3 --import"
	if argv != want {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestGenRevokeAnswersRejectsBadReason(t *testing.T) {
	if _, err := GenRevokeAnswers(4, ""); err == nil {
		t.Error("reason 4 accepted")
	}
	if _, err := GenRevokeAnswers(-1, ""); err == nil {
		t.Error("reason -1 accepted")
	}
}

func TestGenRevokeAnswersRejectsMultiLineDescription(t *testing.T) {
	for _, description := range []string{"stolen\n\ny", "a\rb", "tab\there"} {
		if _, err := GenRevokeAnswers(RevokeCompromised, description); err == nil {
			t.Errorf("description %q accepted", description)
		}
	}
}

func TestGenRevokeAnswersRepeatTextUntilEmptyLine(t *testing.T) {
	withDescription, _ := GenRevokeAnswers(RevokeRetired, "switched jobs")
	withoutDescription, _ := GenRevokeAnswers(RevokeNoReason, "")

	wantDesc := []PromptAnswer{
		{"gen_revoke.okay", "y"},
		{"ask_revocation_reason.code", "3"},
		{"ask_revocation_reason.text", "switched jobs"},
		{"ask_revocation_reason.text", ""},
		{"ask_revocation_reason.okay", "y"},
	}
	if len(withDescription) != len(wantDesc) {
		t.Fatalf("answers = %+v, want %+v", withDescription, wantDesc)
	}
	for i, answer := range withDescription {
		if answer != wantDesc[i] {
			t.Errorf("answer[%d] = %+v, want %+v", i, answer, wantDesc[i])
		}
	}
	wantPlain := []PromptAnswer{
		{"gen_revoke.okay", "y"},
		{"ask_revocation_reason.code", "0"},
		{"ask_revocation_reason.text", ""},
		{"ask_revocation_reason.okay", "y"},
	}
	if len(withoutDescription) != len(wantPlain) {
		t.Fatalf("answers = %+v, want %+v", withoutDescription, wantPlain)
	}
	for i, answer := range withoutDescription {
		if answer != wantPlain[i] {
			t.Errorf("answer[%d] = %+v, want %+v", i, answer, wantPlain[i])
		}
	}
}

func TestAnswerFeederAnswersInOrderAndHandlesRepeats(t *testing.T) {
	answers, _ := GenRevokeAnswers(RevokeSuperseded, "new key")
	feeder := newAnswerFeeder(answers)
	var written []string
	feeder.attach(func(answer string) error {
		written = append(written, answer)
		return nil
	}, func() { t.Error("abort called on expected prompts") })

	for _, line := range []StatusLine{
		{Keyword: "KEY_CONSIDERED", Args: []string{"ABCD", "0"}},
		{Keyword: "GET_BOOL", Args: []string{"gen_revoke.okay"}},
		{Keyword: "GOT_IT"},
		{Keyword: "GET_LINE", Args: []string{"ask_revocation_reason.code"}},
		{Keyword: "GOT_IT"},
		{Keyword: "GET_LINE", Args: []string{"ask_revocation_reason.text"}},
		{Keyword: "GET_LINE", Args: []string{"ask_revocation_reason.text"}},
		{Keyword: "GET_BOOL", Args: []string{"ask_revocation_reason.okay"}},
	} {
		feeder.observe(line)
	}

	want := []string{"y\n", "2\n", "new key\n", "\n", "y\n"}
	if strings.Join(written, "|") != strings.Join(want, "|") {
		t.Errorf("written = %q, want %q", written, want)
	}
}

func TestAnswerFeederAbortsOnUnexpectedPrompt(t *testing.T) {
	feeder := newAnswerFeeder([]PromptAnswer{{Keyword: "gen_revoke.okay", Answer: "y"}})
	aborted := false
	feeder.attach(func(string) error { return nil }, func() { aborted = true })

	feeder.observe(StatusLine{Keyword: "GET_HIDDEN", Args: []string{"passphrase.enter"}})

	if !aborted {
		t.Error("unexpected prompt did not abort")
	}
	if feeder.unexpectedPrompt() != "passphrase.enter" {
		t.Errorf("unexpectedPrompt = %q", feeder.unexpectedPrompt())
	}
}

func TestAnswerFeederIgnoresPromptsAfterStop(t *testing.T) {
	feeder := newAnswerFeeder([]PromptAnswer{{Keyword: "gen_revoke.okay", Answer: "y"}})
	feeder.attach(func(string) error {
		t.Error("write after stop")
		return nil
	}, nil)
	feeder.stop()

	feeder.observe(StatusLine{Keyword: "GET_BOOL", Args: []string{"gen_revoke.okay"}})
}
