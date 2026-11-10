package gpg

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// commandFDStr is the fd gpg reads prompt answers from when a Command carries
// interactive answers (fd 4, the second entry of exec.Cmd.ExtraFiles).
const commandFDStr = "4"

// Revocation reason codes accepted by gpg's ask_revocation_reason menu
// (g10/revoke.c); identical on gpg 2.2 and 2.4+.
const (
	RevokeNoReason    = 0
	RevokeCompromised = 1
	RevokeSuperseded  = 2
	RevokeRetired     = 3
)

// PromptAnswer is one scripted answer to a gpg prompt. Commands with answers
// run without --batch, with --no-tty and --command-fd: gpg emits each prompt
// keyword as a GET_LINE/GET_BOOL status line and reads the answer from the
// command fd. Answers are queued per keyword and consumed in order, which
// handles repeated prompts (gpg asks ask_revocation_reason.text until an
// empty line ends the description).
type PromptAnswer struct {
	Keyword string
	Answer  string
}

// GenRevokeAnswers scripts the prompts of --gen-revoke for a revocation with
// the given reason code and optional single-line description.
func GenRevokeAnswers(reasonCode int, description string) ([]PromptAnswer, error) {
	if reasonCode < RevokeNoReason || reasonCode > RevokeRetired {
		return nil, fmt.Errorf("revocation reason code %d out of range 0-3", reasonCode)
	}
	// A newline would end this answer early and feed the rest to later prompts.
	if strings.ContainsFunc(description, unicode.IsControl) {
		return nil, errors.New("revocation description must be a single line without control characters")
	}
	answers := []PromptAnswer{
		{Keyword: "gen_revoke.okay", Answer: "y"},
		{Keyword: "ask_revocation_reason.code", Answer: strconv.Itoa(reasonCode)},
	}
	if description != "" {
		answers = append(answers, PromptAnswer{Keyword: "ask_revocation_reason.text", Answer: description})
	}
	answers = append(answers,
		PromptAnswer{Keyword: "ask_revocation_reason.text", Answer: ""}, // empty line ends the description
		PromptAnswer{Keyword: "ask_revocation_reason.okay", Answer: "y"},
	)
	return answers, nil
}

// answerFeeder writes scripted answers to gpg's command fd as the matching
// GET_* status lines arrive. An unexpected prompt aborts gpg rather than
// guessing an answer.
type answerFeeder struct {
	write func(string) error
	abort func()

	mu         sync.Mutex
	queued     map[string][]PromptAnswer
	unexpected string
	finished   bool // set once gpg exited, to ignore stale status lines
}

func newAnswerFeeder(answers []PromptAnswer) *answerFeeder {
	queued := make(map[string][]PromptAnswer, len(answers))
	for _, answer := range answers {
		queued[answer.Keyword] = append(queued[answer.Keyword], answer)
	}
	return &answerFeeder{queued: queued}
}

// attach points the feeder at the command pipe and the abort function.
func (f *answerFeeder) attach(write func(string) error, abort func()) {
	f.mu.Lock()
	f.write, f.abort = write, abort
	f.mu.Unlock()
}

// stop marks gpg as gone so late status lines no longer trigger writes.
func (f *answerFeeder) stop() {
	f.mu.Lock()
	f.finished = true
	f.mu.Unlock()
}

// observe answers one GET_* prompt, mirroring the interrupt forwarder's
// view of the status stream.
func (f *answerFeeder) observe(line StatusLine) {
	if line.Keyword != "GET_LINE" && line.Keyword != "GET_BOOL" && line.Keyword != "GET_HIDDEN" {
		return
	}
	if len(line.Args) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finished {
		return
	}
	keyword := line.Args[0]
	queued := f.queued[keyword]
	if len(queued) == 0 {
		f.unexpected = keyword
		if f.abort != nil {
			f.abort()
		}
		return
	}
	f.queued[keyword] = queued[1:]
	if f.write != nil {
		_ = f.write(queued[0].Answer + "\n") // EPIPE once gpg exits is not an error
	}
}

// unexpectedPrompt returns the keyword of a prompt we had no answer for.
func (f *answerFeeder) unexpectedPrompt() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unexpected
}
