// Command tpmroots makes the set of pinned TPM manufacturer roots
// (secureenclave/tpmroots) from the files of Microsoft's TrustedTpm package
// (https://go.microsoft.com/fwlink/?linkid=2097925, a .cab that holds, for each
// maker, a RootCA and an IntermediateCA folder), extracted into one directory.
//
//	go run ./tools/tpmroots -in <extracted dir> -out secureenclave/tpmroots -source <url> -sha256 <of the .cab>
//
// It takes the certificates in each maker's RootCA folder only, drops any that is
// unreadable, and writes one PEM per certificate named by the SHA-256 of its DER,
// with SOURCE.txt saying where they came from. It prints each one's subject and
// expiry so the set can be read before it is committed. It does not decide whom
// to trust: that is the owner's call, made by committing the files.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func main() {
	in := flag.String("in", "", "the extracted TrustedTpm package")
	out := flag.String("out", "", "where to write the PEM files")
	source := flag.String("source", "https://go.microsoft.com/fwlink/?linkid=2097925", "where the package was fetched")
	sum := flag.String("sha256", "", "the SHA-256 of the package file, as fetched")
	flag.Parse()
	if *in == "" || *out == "" || *sum == "" {
		fmt.Fprintln(os.Stderr, "usage: tpmroots -in DIR -out DIR -sha256 HEX [-source URL]")
		os.Exit(2)
	}
	files, _ := filepath.Glob(filepath.Join(*in, "*", "RootCA", "*"))
	sort.Strings(files)
	seen := map[string]bool{}
	var lines []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if b, _ := pem.Decode(raw); b != nil {
			raw = b.Bytes
		}
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipped %s: %v\n", f, err)
			continue
		}
		h := sha256.Sum256(c.Raw)
		id := hex.EncodeToString(h[:])
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := os.WriteFile(filepath.Join(*out, id+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		lines = append(lines, fmt.Sprintf("%s  %s  expires %s  (%s)", id, c.Subject, c.NotAfter.Format("2006-01-02"), filepath.Base(filepath.Dir(filepath.Dir(f)))))
	}
	note := fmt.Sprintf("Made by tools/tpmroots on %s from %s\nSHA-256 of the package as fetched: %s\n\n", time.Now().UTC().Format("2006-01-02"), *source, *sum)
	for _, l := range lines {
		note += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(*out, "SOURCE.txt"), []byte(note), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(note)
}
