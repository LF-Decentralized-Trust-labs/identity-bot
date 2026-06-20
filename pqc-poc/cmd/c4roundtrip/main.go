package main

import (
	"fmt"
	"os"

	"identity-bot/pqc-poc/roundtrip"
)

func main() {
	res, err := roundtrip.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS:", res.String())
	if !res.SigVerifyOK || !res.KemSecretOK {
		fmt.Fprintln(os.Stderr, "FAIL: round-trip checks returned false")
		os.Exit(1)
	}
}