package server

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/recovery"
)

// Activate can refuse for four different reasons and a client has to be able to
// tell them apart.
//
// Two of them used to fall to the default branch and arrive as 400 "could not
// complete this recovery" — which is what a mistyped phrase also looks like. So
// no screen could distinguish "this is being held for another two days" from
// "those words are wrong".

func TestEachRefusalGetsItsOwnStatus(t *testing.T) {
	for _, c := range []struct {
		what string
		err  error
		want int
	}{
		{"still inside the waiting period", &recovery.ErrCancelWindowActive{
			CompleteAfter: time.Now().Add(time.Hour), Remaining: time.Hour,
		}, http.StatusConflict},
		{"the mandatory rotation is not done", &recovery.ErrRotationMandatory{
			SessionID: "abc",
		}, http.StatusPreconditionFailed},
		{"held because somebody may be being forced", &recovery.ErrHeldForDuress{
			Reason: "this identity holds a recovery", NeedsApprovals: 1,
		}, http.StatusConflict},
		{"nothing could establish who is here", &recovery.ErrNotAuthenticated{
			Required: authprovider.LevelVerified,
			Got:      authprovider.Unmeasured("no provider"),
		}, http.StatusForbidden},
	} {
		if got := statusForActivateError(c.err); got != c.want {
			t.Fatalf("%s answered %d, wanted %d", c.what, got, c.want)
		}
	}

	// Anything else is the caller's to fix.
	if got := statusForActivateError(
		errors.New("those words do not open this archive")); got != http.StatusBadRequest {
		t.Fatalf("an ordinary refusal answered %d", got)
	}
}

func TestARefusalIsNeverReportedAsThisAgentFailing(t *testing.T) {
	// 500 would say the agent broke. Every one of these is a true statement
	// about the request or about where the recovery has got to, and somebody
	// reading it should be able to act on it.
	for _, err := range []error{
		&recovery.ErrCancelWindowActive{Remaining: time.Hour},
		&recovery.ErrRotationMandatory{SessionID: "abc"},
		&recovery.ErrHeldForDuress{Reason: "held"},
		&recovery.ErrNotAuthenticated{Required: authprovider.LevelBasic},
		errors.New("a wrong phrase"),
	} {
		if s := statusForActivateError(err); s >= 500 {
			t.Fatalf("%T was reported as a server fault (%d)", err, s)
		}
	}
}

func TestAHeldRecoveryIsNotTheSameAsAWrongPhrase(t *testing.T) {
	// The distinction the default branch destroyed. If these two ever answer
	// the same status again, no client can branch on them.
	held := statusForActivateError(&recovery.ErrHeldForDuress{Reason: "held"})
	wrong := statusForActivateError(errors.New("those words do not open this archive"))
	if held == wrong {
		t.Fatalf("a duress hold and a wrong phrase both answer %d", held)
	}

	notAuth := statusForActivateError(&recovery.ErrNotAuthenticated{
		Required: authprovider.LevelVerified,
	})
	if notAuth == wrong {
		t.Fatalf("a failed authentication and a wrong phrase both answer %d", notAuth)
	}
}
