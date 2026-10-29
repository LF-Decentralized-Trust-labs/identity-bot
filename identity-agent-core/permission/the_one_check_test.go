package permission

import (
	"strings"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

func atScore(score int) Person {
	return Person{AID: "ESomebody", Authenticated: authprovider.Result{
		Score: score, Measured: true, At: time.Now().UTC(), Level: authprovider.LevelForScore(score),
	}}
}

// The default minimum is 80, and the placeholder every person has today meets it.
func TestThePlaceholderScoreMeetsTheDefaultMinimum(t *testing.T) {
	who := Person{AID: "ESomebody", Authenticated: authprovider.UntilHumanAuthenticationIsBuilt(time.Now())}
	if ok, why := MayThisPersonDoThis(Action{Name: "anything"}, who); !ok {
		t.Fatalf("the placeholder score was refused an action with the default minimum: %s", why)
	}
	if ok, _ := MayThisPersonDoThis(Action{Name: "anything"}, atScore(79)); ok {
		t.Fatal("a score of 79 cleared the default minimum of 80")
	}
}

// An action whose minimum is set to 90 is refused at the placeholder 80, and
// the refusal names the score question.
func TestAnActionNeedingNinetyIsRefusedAtEighty(t *testing.T) {
	who := Person{AID: "ESomebody", Authenticated: authprovider.UntilHumanAuthenticationIsBuilt(time.Now())}
	ok, why := MayThisPersonDoThis(Action{Name: "high", MinimumScore: 90}, who)
	if ok {
		t.Fatal("an action needing 90 was allowed at 80")
	}
	if !strings.Contains(why, "90") || !strings.Contains(why, "80") {
		t.Fatalf("the refusal does not say which score was needed and which was had: %s", why)
	}
	if ok, _ := MayThisPersonDoThis(Action{Name: "high", MinimumScore: 90}, atScore(95)); !ok {
		t.Fatal("a score of 95 was refused an action needing 90")
	}
}

// Nothing measured is not a score of zero that might clear a low minimum.
func TestNothingMeasuredClearsNothing(t *testing.T) {
	who := Person{AID: "ESomebody", Authenticated: authprovider.Unmeasured("nothing")}
	if ok, _ := MayThisPersonDoThis(Action{Name: "low", MinimumScore: 1}, who); ok {
		t.Fatal("an unmeasured person cleared a minimum of 1")
	}
}

// A minimum that is not a score refuses everybody rather than letting
// everybody through.
func TestANegativeMinimumRefusesEverybody(t *testing.T) {
	if ok, _ := MayThisPersonDoThis(Action{Name: "typo", MinimumScore: -5}, atScore(100)); ok {
		t.Fatal("a negative minimum let a caller through")
	}
}
