package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The approval list names the device a grant waits for, from the name given
// when that device was adopted: only on what waits for it, and only when a
// name was given.
func TestTheApprovalListNamesTheDeviceThatHoldsTheKey(t *testing.T) {
	list := func(e *elsewhere) []map[string]any {
		rec := httptest.NewRecorder()
		e.s.router.ServeHTTP(rec, local("GET", "/api/grants/awaiting-approval", ""))
		var out struct {
			Machines []map[string]any `json:"machines"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%v: %s", err, rec.Body.String())
		}
		return out.Machines
	}
	adopt := func(e *elsewhere, name string) {
		oa, err := e.s.ownerAuthority()
		if err != nil || oa == nil {
			t.Fatalf("no owner: %v", err)
		}
		if err := e.s.rememberPeerFromAdoption(ownerDID(t, oa.AID), "https://owner.example", name); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("a given name is shown on what waits for that device", func(t *testing.T) {
		e := keyElsewhere(t)
		e.pairMachine(t, grantFor(5, GradeEnrolled))
		adopt(e, "  Rob's\tiPhone ")
		ms := list(e)
		if len(ms) != 1 || ms[0]["awaiting"] != awaitingWhat(true) || ms[0]["key_device_name"] != "Rob's iPhone" {
			t.Fatalf("the list: %v", ms)
		}
	})
	t.Run("no name given, none is made up", func(t *testing.T) {
		e := keyElsewhere(t)
		e.pairMachine(t, grantFor(5, GradeEnrolled))
		adopt(e, "")
		ms := list(e)
		if len(ms) != 1 {
			t.Fatalf("the list: %v", ms)
		}
		if _, has := ms[0]["key_device_name"]; has {
			t.Fatalf("a name was invented: %v", ms[0])
		}
	})
	t.Run("a grant that waits for the owner is not said to wait for the device", func(t *testing.T) {
		e := keyElsewhere(t)
		adopt(e, "Rob's iPhone")
		// Paired with no grant at all: awaits the owner's approval, not the device.
		if err := e.s.controllers().Put(grantFor(6, GradeEnrolled)); err != nil {
			t.Fatal(err)
		}
		for _, m := range list(e) {
			if m["awaiting"] == awaitingWhat(false) {
				if _, has := m["key_device_name"]; has {
					t.Fatalf("named on something that waits for the owner: %v", m)
				}
			}
		}
	})
}

func TestADeviceNameIsFitToShow(t *testing.T) {
	long := strings.Repeat("é", maxDeviceNameRunes+20)
	for in, want := range map[string]string{
		"":                "",
		" \x00\x07 ":      "",
		"Rob's\n\tiPhone": "Rob's iPhone",
		long:              strings.Repeat("é", maxDeviceNameRunes),
	} {
		if got := cleanDeviceName(in); got != want {
			t.Errorf("cleanDeviceName(%q) = %q, want %q", in, got, want)
		}
	}
}
