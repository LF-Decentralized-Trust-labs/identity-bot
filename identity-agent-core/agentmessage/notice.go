package agentmessage

import (
	"errors"
	"fmt"
)

// KindNotice is the Identity Agent telling a person something in a conversation,
// in words that are fixed (ADR-081). It is the Identity Agent's own entry, like an
// outcome: it carries no sender's proof, and the countersignature is the whole
// proof. It names a code, never words, so the trail keeps what was said without
// keeping any text (ADR-068), and every reader shows the same words for a code.
const KindNotice = "notice"

// Codes a notice may name, and what each says.
const (
	// NoticeNotesKept tells a person that notes may be kept about them, and that
	// they can see and delete them.
	NoticeNotesKept = "notes-kept-about-you"
)

var noticeWords = map[string]string{
	NoticeNotesKept: "Notes may be kept about you by the AI agents of this organisation. You will be invited to a page where you can see them and delete them.",
}

// Notice is what a notice entry says: a code.
type Notice struct {
	Code string `json:"code"`
}

// NoticeWords is the fixed words of a code, and whether it is one.
func NoticeWords(code string) (string, bool) {
	w, ok := noticeWords[code]
	return w, ok
}

// checkNotice checks a notice record: the Identity Agent's, for a person, with
// a code that has words, no proof of a sender's, nothing it replies to and no words of its own.
func (r Record) checkNotice() error {
	if r.Statement != nil || r.ControllerProof != nil || r.PersonProof != nil || r.Refusal != "" || r.CiphertextHash != "" {
		return errors.New("a notice carries no sender's proof")
	}
	if r.Kind != KindNotice {
		return errors.New("a notice is of the kind notice")
	}
	if _, ok := noticeWords[r.Notice.Code]; !ok {
		return fmt.Errorf("%q is not a notice the Identity Agent gives", r.Notice.Code)
	}
	if _, person := IsPerson(r.To); !person {
		return errors.New("a notice is for a person")
	}
	if r.InReplyTo != "" {
		return errors.New("a notice acts on no message")
	}
	if r.BodyHash != HashBody(nil) {
		return errors.New("a notice carries no words of its own: the code is what it says")
	}
	return nil
}
