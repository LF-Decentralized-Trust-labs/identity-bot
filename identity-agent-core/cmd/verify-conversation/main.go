// Command verify-conversation checks an exported conversation between AI
// agents, offline.
//
//	verify-conversation [--json] <bundle.json>
//
// It reads the bundle an Identity Agent exported and checks it with nothing
// else: no network, no Identity Agent. It prints what held, what did not, which
// messages fall after the last anchor, and exactly what the result trusts.
//
// Exit status: 0 when the conversation verifies, 1 when it does not, 2 when the
// bundle cannot be read.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"identity-agent-core/conversationbundle"
)

// maxBundle bounds what is read: a conversation is at most a few hundred
// messages of at most 64 KiB each, with their proofs.
const maxBundle = 256 << 20

func main() {
	asJSON := flag.Bool("json", false, "print the report as JSON")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: verify-conversation [--json] <bundle.json>")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	report, err := verifyFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-conversation:", err)
		os.Exit(2)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Print(report.Text())
	}
	if !report.Verified {
		os.Exit(1)
	}
}

// verifyFile reads a bundle and checks it.
func verifyFile(path string) (conversationbundle.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return conversationbundle.Report{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBundle+1))
	if err != nil {
		return conversationbundle.Report{}, err
	}
	if len(data) > maxBundle {
		return conversationbundle.Report{}, fmt.Errorf("%s is larger than any bundle this reads", path)
	}
	b, err := conversationbundle.Read(data)
	if err != nil {
		return conversationbundle.Report{}, fmt.Errorf("%s is not a conversation bundle: %w", path, err)
	}
	return conversationbundle.Verify(b), nil
}
