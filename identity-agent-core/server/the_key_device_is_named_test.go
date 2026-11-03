package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/schemas"
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

// An add-on's items are named by the flag the add-on sets, not by comparing
// the wording of "awaiting": an AI agent whose own phrase differs from the
// core's still gets the name, and one not waiting for that device does not.
func TestAnAIAgentWaitingForTheKeyDeviceIsNamed(t *testing.T) {
	e := keyElsewhere(t)
	oa, _ := e.s.ownerAuthority()
	if err := e.s.rememberPeerFromAdoption(ownerDID(t, oa.AID), "https://owner.example", "Rob's iPhone"); err != nil {
		t.Fatal(err)
	}
	host := hostWrapper{s: e.s}
	onlyAddons(t, Addon{ID: "test-agents", GrantKinds: map[*schemas.AssetGrant]GrantKind{nil: {
		AwaitingKey: "agents",
		Awaiting: func(s *CoreServer) []map[string]any {
			return []map[string]any{
				{"agent_aid": "Ewaits", "awaiting": "waiting for its grant to be signed on the device…", waitingForKeyDevice: host.WaitsForKeyDevice(true)},
				{"agent_aid": "Eowner", "awaiting": "awaiting the owner's approval", waitingForKeyDevice: host.WaitsForKeyDevice(false)},
			}
		},
	}}})
	rec := httptest.NewRecorder()
	e.s.router.ServeHTTP(rec, local("GET", "/api/grants/awaiting-approval", ""))
	var out struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	if len(out.Agents) != 2 || out.Agents[0]["key_device_name"] != "Rob's iPhone" {
		t.Fatalf("the agent waiting for the device is not named: %v", out.Agents)
	}
	if _, has := out.Agents[1]["key_device_name"]; has {
		t.Fatalf("an agent waiting for the owner was named: %v", out.Agents[1])
	}
}

// A machine whose grant the device refused, or which expired, still waits for
// that device: the owner is told which one and to ask again.
func TestARefusedOrExpiredMachineIsStillNamed(t *testing.T) {
	for _, state := range []string{SigningStatusRefused, SigningStatusExpired} {
		t.Run(state, func(t *testing.T) {
			e := keyElsewhere(t)
			oa, _ := e.s.ownerAuthority()
			if err := e.s.rememberPeerFromAdoption(ownerDID(t, oa.AID), "https://owner.example", "Rob's iPhone"); err != nil {
				t.Fatal(err)
			}
			e.pairMachine(t, grantFor(5, GradeEnrolled))
			req := waiting(t, e.s)[0]
			stored, err := e.s.DataStore.GetSigningRequest(req.ID)
			if err != nil || stored == nil {
				t.Fatalf("no request: %v", err)
			}
			stored.Status = state
			stored.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			if err := e.s.DataStore.SaveSigningRequest(*stored); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			e.s.router.ServeHTTP(rec, local("GET", "/api/grants/awaiting-approval", ""))
			var out struct {
				Machines []map[string]any `json:"machines"`
			}
			json.Unmarshal(rec.Body.Bytes(), &out)
			if len(out.Machines) != 1 || !strings.HasSuffix(out.Machines[0]["awaiting"].(string), "ask again") ||
				out.Machines[0]["key_device_name"] != "Rob's iPhone" {
				t.Fatalf("the list: %v", out.Machines)
			}
		})
	}
}

func TestAFormatCharacterCannotDisguiseADeviceName(t *testing.T) {
	for in, want := range map[string]string{
		"Rob\u202e's iPhone":     "Rob's iPhone",
		"Ro\u200bb":              "Rob",
		"\u202e\u200b\U0000feff": "",
		"open \u2066evil\u2069":  "open evil",
	} {
		if got := cleanDeviceName(in); got != want {
			t.Errorf("cleanDeviceName(%q) = %q, want %q", in, got, want)
		}
	}
}
