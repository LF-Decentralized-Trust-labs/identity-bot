package keymath

import (
	"fmt"
	"io"
)

// MaxRequestBytes bounds what the keymath command reads: an event to parse,
// or a message to sign, and no more.
const MaxRequestBytes = 1 << 20

// Command is the keymath command a desktop app runs the core binary as:
// `<core> keymath <operation>`, with the request on standard input and the
// answer on standard output. It opens no port, writes no file and reads no
// secret from its arguments, which other processes on the machine can read;
// the operation is the only argument. A refusal goes to standard error, and
// never repeats the request.
func Command(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(errOut, "usage: keymath <operation> < request.json")
		return 2
	}
	req, err := io.ReadAll(io.LimitReader(in, MaxRequestBytes+1))
	if err != nil || len(req) > MaxRequestBytes {
		fmt.Fprintln(errOut, "the request could not be read")
		zero(req)
		return 2
	}
	answer, err := Do(args[0], req)
	zero(req)
	if err != nil {
		fmt.Fprintln(errOut, err.Error())
		return 1
	}
	out.Write(answer)
	out.Write([]byte("\n"))
	return 0
}
