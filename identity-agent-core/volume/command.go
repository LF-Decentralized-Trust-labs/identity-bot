package volume

// The commands that run against an Identity Agent's data volume, in one place.
//
// These execute before the Identity Agent does, or instead of it — preparing the
// encrypted volume at first boot, and adding an owner's way back into it at
// adoption. They are subcommands of the Identity Agent binary rather than
// separate tools, because a sealed image measures what is inside it and one
// binary is one thing to measure.
//
// They live behind a single entry point because an embedder that re-implements
// the dispatch can silently omit one of them. A
// sealed image runs whichever binary it was built with, and an organisation
// image is built with an overlay of this core rather than this core itself.
// The overlay dispatched neither subcommand, so systemd ran
//
//	identity-agent-core seal-volume /dev/vdb tenant-data
//
// the overlay ignored the arguments and tried to start a server on a read-only
// root, and exited in 200ms. The volume was never encrypted, the state mount
// failed on the dependency, and the Identity Agent crash-looped against a data
// directory it could not create — none of which mentions the actual cause.
//
// Two mirrored if-statements, one per binary, is what made that possible.
// One dispatcher means an overlay wires up every command by wiring up nothing,
// and a command added later reaches every binary that embeds this core.

// commands is every volume subcommand, by the name the sealed image invokes.
//
// A lookup rather than a switch inside Handle, so that "does this name route?"
// can be answered without running the command. That distinction is not
// academic: seal-volume with a complete argument list LUKS-formats the device
// it is given, so a test that answered the routing question by calling Handle
// would erase a tenant's data volume on exactly the machines this code exists
// for — a sealed host, as root, with an unformatted volume present.
var commands = map[string]func([]string) error{
	"seal-volume":        seal,
	"add-owner-recovery": addOwnerRecoveryCommand,
}

// Command returns the volume subcommand args names, or nil.
//
// Exported for tests and for an embedder that wants to know whether it is
// about to shadow a command name, neither of which should have to execute one
// to find out.
func Command(args []string) func([]string) error {
	if len(args) < 1 {
		return nil
	}
	return commands[args[0]]
}

// Handle runs a volume subcommand if args names one.
//
// Returns handled=false when args is not a volume command, which is the signal
// to carry on and start the Identity Agent normally. A caller that ignores the
// return and starts a server anyway reproduces the fault this exists to
// prevent.
//
// handled=false always comes with a nil error: nothing here inspects arguments
// before deciding whether they are ours, so there is no way to fail while
// declining. A caller may rely on that, and the test below holds it to it —
// otherwise the obvious `if handled { ... }` at the call site would swallow an
// error, which is the silent shape this package exists to remove.
func Handle(args []string) (handled bool, err error) {
	cmd := Command(args)
	if cmd == nil {
		return false, nil
	}
	return true, cmd(args[1:])
}
