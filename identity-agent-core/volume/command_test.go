package volume

import "testing"

// What the dispatcher has to get right, and what went wrong without it.
//
// A sealed image runs whichever Identity Agent binary it was built with. An
// image built from an overlay of this core dispatched neither subcommand, so
// the image ran seal-volume, the overlay ignored the arguments and started a
// server instead, and the volume was silently never encrypted. Nothing in the
// resulting crash mentioned the volume: it surfaced three steps downstream, as
// a database that could not be opened.
//
// These tests ask whether a name routes, and never run what it routes to.
// seal-volume with a complete argument list LUKS-formats the device it is
// given, so a routing test written as a call to Handle would erase a tenant's
// data volume on precisely the machines this code exists for. That is why
// Command exists separately: "does this name reach a command" is answerable
// without also answering "and what does that command do".

func TestTheVolumeCommandsAreRecognised(t *testing.T) {
	for _, name := range []string{"seal-volume", "add-owner-recovery"} {
		if Command([]string{name}) == nil {
			t.Errorf("%q does not route, so a binary embedding this core would start a "+
				"server where a volume command was intended", name)
		}
	}
}

func TestAnythingElseIsNotHandled(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{},
		{"serve"},
		{"--help"},
		{"seal"},           // near-miss
		{"volume", "seal"}, // right words, wrong order
	} {
		if Command(args) != nil {
			t.Errorf("%v routes to a volume command, so the Identity Agent would never start", args)
		}
		// Declining must never fail. Handle's contract says handled=false comes
		// with a nil error, and the obvious call site relies on it.
		handled, err := Handle(args)
		if handled {
			t.Errorf("%v was handled", args)
		}
		if err != nil {
			t.Errorf("%v is not ours and should not produce an error: %v", args, err)
		}
	}
}

// tools/sealed-image/build-sealed-image.sh writes a systemd unit invoking
// exactly this argument list, and nothing but this test compares the two. A
// rename here that misses that script leaves every instance booting with an
// unencrypted volume, and the failure surfaces three steps downstream.
//
// Routing only. Calling it would format the device.
func TestTheNameTheSealedImageInvokesStillRoutes(t *testing.T) {
	if Command([]string{"seal-volume", "/dev/vdb", "tenant-data"}) == nil {
		t.Fatal("the sealed image's seal-volume.service invokes this exact argument list; " +
			"if it no longer routes, every instance boots with an unencrypted volume")
	}
}

// Each command still refuses an argument list it cannot use. Reached through
// the table rather than through Handle so nothing here can touch a device:
// every case is short of the arguments a command needs to act.
func TestEachCommandRefusesTooFewArguments(t *testing.T) {
	for name, cmd := range commands {
		if err := cmd(nil); err == nil {
			t.Errorf("%q accepted an empty argument list", name)
		}
	}
}
