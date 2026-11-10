package login

import (
	"encoding/json"
	"fmt"

	"identity-agent-core/internal/strictjson"
)

// SignInPost is what a person's Identity Agent posts to a callback when it
// presented credentials (ADR-071): the signed assertion, which names each
// credential by digest, and the credentials themselves, which are for the
// website owner's Identity Agent alone. An assertion that presented nothing is
// posted bare, as before.
type SignInPost struct {
	Assertion   json.RawMessage       `json:"assertion"`
	Credentials []PresentedCredential `json:"credentials"`
}

// SignInPostBody is the body to post for assertion and the credentials it names.
func SignInPostBody(a *Assertion, creds []PresentedCredential) ([]byte, error) {
	ab, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return ab, nil
	}
	return json.Marshal(SignInPost{Assertion: ab, Credentials: creds})
}

// ReadSignInPost reads a callback's body: the assertion exactly as sent (the
// text a page's collector is handed), the assertion read by ReadAssertion's
// rules, and any credentials posted beside it. A bare assertion, which is
// every sign-in that presented nothing and every one from an Identity Agent
// that has not updated, has none.
func ReadSignInPost(body []byte) (raw []byte, a Assertion, creds []PresentedCredential, err error) {
	var keys map[string]json.RawMessage
	if json.Unmarshal(body, &keys) != nil {
		a, err = ReadAssertion(body)
		return body, a, nil, err
	}
	if _, wrapped := keys["assertion"]; !wrapped {
		a, err = ReadAssertion(body)
		return body, a, nil, err
	}
	var post SignInPost
	if err = strictjson.Decode(body, &post); err != nil {
		return nil, Assertion{}, nil, fmt.Errorf("the sign-in cannot be read: %w", err)
	}
	a, err = ReadAssertion(post.Assertion)
	if err != nil {
		return nil, Assertion{}, nil, err
	}
	return post.Assertion, a, post.Credentials, nil
}

// DigestsOnly reports whether every credential an assertion presents is named
// by digest. An assertion in the form before ADR-071 carries the credentials
// themselves, and must go to no page.
func DigestsOnly(a Assertion) bool {
	for _, p := range a.PresentedACDCs {
		if _, ok := p.(string); !ok {
			return false
		}
	}
	return true
}
