// Command driver runs the Windows front end's TPM code (the C++ in
// packages/login-flutter/windows/tpm2.cpp, built as test/tpm2_cli) against a
// software TPM, the reference implementation of the TPM 2.0 library, and checks
// everything it makes with the Identity Agent's own code:
//
//   - the endorsement key it makes is the standard EK, the one a certificate certifies;
//   - the credential the core makes (MakeTPMCredential) is opened by that TPM, in the
//     C++'s TPM2_ActivateCredential, with the policy session an EK needs;
//   - the key's evidence is accepted by VerifyTPMKeyCertify, which proves the key is
//     a restricted-signing-key-certified, non-exportable P-256 key made in that TPM;
//   - the key's signatures verify under the point it gave.
//
// It cannot test Windows: TBS, a real manufacturer's chain, or what a Windows
// install allows a program to do with a TPM. Run, from this folder:
//
//	g++ -std=c++17 -O1 ../../../../packages/login-flutter/windows/test/tpm2_cli.cpp \
//	    ../../../../packages/login-flutter/windows/tpm2.cpp -o /tmp/tpm2_cli
//	go run ./driver -cli /tmp/tpm2_cli
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"

	"identity-agent-core/secureenclave"
)

var failed bool

func check(ok bool, what string, args ...any) {
	if ok {
		fmt.Println("ok   ", fmt.Sprintf(what, args...))
		return
	}
	failed = true
	fmt.Println("FAIL ", fmt.Sprintf(what, args...))
}

func must(err error, what string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, what+":", err)
		os.Exit(1)
	}
}

func sized(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
func h(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}
func unh(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	must(err, "hex")
	return b
}

func main() {
	cli := flag.String("cli", "", "the built tpm2_cli")
	flag.Parse()
	sim, err := simulator.Get()
	must(err, "simulator")
	defer sim.Close()

	// A test root and the EK certificate it signs for the simulator's own EK (the
	// standard template, which the C++ must reproduce exactly).
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tpmsim test root (not a manufacturer)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	must(err, "root")
	root, _ := x509.ParseCertificate(rootDER)
	ek, err := client.EndorsementKeyRSA(sim)
	must(err, "EK")
	ekWire, _ := ek.PublicArea().Encode()
	ekDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tpmsim EK"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}, root, ek.PublicKey(), rootKey)
	must(err, "EK certificate")
	ek.Close()

	// The simulator, over a unix socket, for the C++.
	dir, _ := os.MkdirTemp("", "tpmsim")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "tpm.sock")
	ln, err := net.Listen("unix", sock)
	must(err, "listen")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		for {
			head := make([]byte, 10)
			if _, err := io.ReadFull(c, head); err != nil {
				return
			}
			size := int(head[2])<<24 | int(head[3])<<16 | int(head[4])<<8 | int(head[5])
			cmd := make([]byte, size)
			copy(cmd, head)
			if _, err := io.ReadFull(c, cmd[10:]); err != nil {
				return
			}
			if _, err := sim.Write(cmd); err != nil {
				return
			}
			resp := make([]byte, 8192)
			n, err := sim.Read(resp)
			if err != nil {
				return
			}
			if _, err := c.Write(resp[:n]); err != nil {
				return
			}
		}
	}()

	cmd := exec.Command(*cli, sock)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	must(cmd.Start(), "start the C++")
	out := bufio.NewReader(stdout)
	ask := func(line string) []string {
		fmt.Fprintln(stdin, line)
		l, err := out.ReadString('\n')
		must(err, "the C++ said nothing")
		return strings.Fields(l)
	}
	roots := []*x509.Certificate{root}

	// 1. Enrol: the C++ makes the attestation key and reads the endorsement key.
	e := ask("enrol app " + h(ekDER))
	check(e[0] == "OK", "enrol is answered: %v", e[:1])
	if e[0] != "OK" {
		fmt.Println(e)
		os.Exit(1)
	}
	ekPub, akPub := unh(e[1]), unh(e[3])
	check(bytes.Equal(ekPub, sized(ekWire)), "the endorsement key it makes is the standard EK (the one a certificate certifies)")

	// 2. The Identity Agent's half: a credential for that EK and AK.
	credKey := make([]byte, 32)
	rand.Read(credKey)
	challenge := make([]byte, 32)
	rand.Read(challenge)
	cred, err := secureenclave.MakeTPMCredentialAgainstRoots(ekPub, ekDER, nil, akPub, credKey, now, roots)
	must(err, "the core's credential")

	// 3. A credential for another attestation key is not opened by the TPM.
	other := append([]byte(nil), cred.CredentialBlob...)
	other[len(other)-1] ^= 1
	bad := ask(fmt.Sprintf("attest app %s %s %s", h(challenge), h(other), h(cred.Secret)))
	check(bad[0] == "ERR", "a credential that was tampered with is refused by the TPM: %v", bad)

	// 4. The real one: the TPM opens it, makes a key and certifies it.
	r := ask(fmt.Sprintf("attest app %s %s %s", h(challenge), h(cred.CredentialBlob), h(cred.Secret)))
	check(r[0] == "OK", "the TPM opens the core's credential and attests a key: %v", r[:1])
	if r[0] != "OK" {
		fmt.Println(r)
		os.Exit(1)
	}
	point, keyPub, info, sig, secret := unh(r[1]), unh(r[2]), unh(r[3]), unh(r[4]), unh(r[5])
	b := func(v []byte) string { return base64.StdEncoding.EncodeToString(v) }
	evidence, _ := json.Marshal(map[string]any{"key_public": b(keyPub), "certify_info": b(info), "certify_signature": b(sig),
		"ak_public": b(akPub), "ek_cert": b(ekDER), "ek_chain": []string{}, "credential_secret": b(secret)})
	facts, err := secureenclave.VerifyTPMKeyCertifyAgainstRoots(evidence, challenge, credKey, now, roots)
	check(err == nil, "the core accepts the evidence the C++ made: %v", err)
	if err == nil {
		check(facts.Platform == "tpm" && !facts.AppIDPresent, "it is a TPM's key and says nothing of which app holds it")
		check(bytes.Equal(elliptic.Marshal(elliptic.P256(), facts.Public.X, facts.Public.Y), point), "the key the core read is the point the C++ gave")
	}
	_, err = secureenclave.VerifyTPMKeyCertifyAgainstRoots(evidence, append([]byte("x"), challenge...), credKey, now, roots)
	check(err != nil, "the evidence is for its own challenge only")

	// 5. The key signs, and the point it gave verifies it.
	p := ask("point app")
	check(p[0] == "OK" && p[1] == r[1], "the point is kept and given again")
	digest := sha256.Sum256([]byte("a sign-in statement"))
	s := ask("sign app " + h(digest[:]))
	check(s[0] == "OK", "the key signs: %v", s[:1])
	if s[0] == "OK" && facts != nil {
		check(ecdsa.VerifyASN1(facts.Public, digest[:], unh(s[1])), "its signature verifies under the attested key")
	}
	stdin.Close()
	cmd.Wait()
	if failed {
		os.Exit(1)
	}
}
