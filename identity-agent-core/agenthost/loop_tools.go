package agenthost

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// The tools agent-host's own loop gives the model, beside the host's: a
// command, and work on files. Each runs as the loop runs, as the brain's
// user, so it reaches what that user may and nothing more (ADR-058).

// The tools' bounds.
const (
	// commandWait is how long a command runs unless the model asks for
	// longer, and commandWaitLongest the longest it may ask for.
	commandWait        = 2 * time.Minute
	commandWaitLongest = 10 * time.Minute
	// commandKept is how much of what a command printed is kept, and
	// toolShown how much of any tool's output the model is shown.
	commandKept = 1 << 20
	toolShown   = 30 << 10
	// readLines and readLargest bound one read of a file.
	readLines   = 2000
	readLargest = 256 << 10
	// listMost and searchMost bound a listing and a search.
	listMost   = 500
	searchMost = 200
	// searchFileLargest is the largest file a search reads.
	searchFileLargest = 4 << 20
)

// skipped are directories a listing and a search pass over.
var skipped = map[string]bool{".git": true, "node_modules": true, loopDir: true}

var workToolList = []chatTool{
	{Name: "run_command", Description: "Run a command in the system shell, in your working directory. Its input " +
		"is empty and nothing can answer a prompt. It is stopped, with everything it started, after timeout_seconds " +
		"(120 unless you ask, at most 600). You are shown its exit status and what it printed, cut to the start " +
		"and the end when it is long.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"command":         map[string]any{"type": "string", "description": "the command line to run"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "how long it may run, at most 600"}},
			"required": []string{"command"}}},
	{Name: "read_file", Description: "Read a text file, by lines, each numbered. At most 2000 lines or 256 KB " +
		"at a time; ask for a later part with offset.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"path":   map[string]any{"type": "string"},
			"offset": map[string]any{"type": "integer", "description": "the first line to read, from 1"},
			"limit":  map[string]any{"type": "integer", "description": "how many lines to read"}},
			"required": []string{"path"}}},
	{Name: "write_file", Description: "Write a file whole, making its folders if they are missing. What it held " +
		"before is replaced.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"path":    map[string]any{"type": "string"},
			"content": map[string]any{"type": "string"}},
			"required": []string{"path", "content"}}},
	{Name: "replace_in_file", Description: "Replace exact text in a file. old_text must occur exactly once, " +
		"unless replace_all is true; copy it exactly, spaces included.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"path":        map[string]any{"type": "string"},
			"old_text":    map[string]any{"type": "string"},
			"new_text":    map[string]any{"type": "string"},
			"replace_all": map[string]any{"type": "boolean"}},
			"required": []string{"path", "old_text", "new_text"}}},
	{Name: "list_files", Description: "List the files under a folder (your working directory unless you name " +
		"one), at most 500, passing over .git and node_modules. pattern, when given, keeps only names that match " +
		"it, such as *.go.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"path":    map[string]any{"type": "string"},
			"pattern": map[string]any{"type": "string"}}}},
	{Name: "search_files", Description: "Search the text of files under a folder for a regular expression (Go's " +
		"syntax), at most 200 matching lines, each as path:line: text. pattern keeps only files whose names match.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"regex":   map[string]any{"type": "string"},
			"path":    map[string]any{"type": "string"},
			"pattern": map[string]any{"type": "string"}},
			"required": []string{"regex"}}},
}

// workTools are the loop's own tools, working in dir.
type workTools struct {
	dir string
}

// use runs one of the loop's own tools.
func (w workTools) use(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var a struct {
		Command        string `json:"command"`
		TimeoutSeconds int    `json:"timeout_seconds"`
		Path           string `json:"path"`
		Offset         int    `json:"offset"`
		Limit          int    `json:"limit"`
		Content        string `json:"content"`
		OldText        string `json:"old_text"`
		NewText        string `json:"new_text"`
		ReplaceAll     bool   `json:"replace_all"`
		Pattern        string `json:"pattern"`
		Regex          string `json:"regex"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "", fmt.Errorf("the arguments do not fit this tool: %v", err)
	}
	switch name {
	case "run_command":
		return w.run(ctx, a.Command, a.TimeoutSeconds)
	case "read_file":
		return w.read(a.Path, a.Offset, a.Limit)
	case "write_file":
		return w.write(a.Path, a.Content)
	case "replace_in_file":
		return w.replace(a.Path, a.OldText, a.NewText, a.ReplaceAll)
	case "list_files":
		return w.list(ctx, a.Path, a.Pattern)
	case "search_files":
		return w.search(ctx, a.Path, a.Regex, a.Pattern)
	}
	return "", fmt.Errorf("there is no tool called %q", name)
}

// path is p taken from the workspace unless it is absolute. The loop's own
// conversations are refused, so a slip cannot overwrite the conversation the
// model is in: by the path as given, and by where it really leads, through
// any link in it or in the folders above it, even to a file not made yet.
func (w workTools) path(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("name a path")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(w.dir, p)
	}
	p = filepath.Clean(p)
	own := filepath.Join(w.dir, loopDir)
	if within(p, own) || within(realPath(p), realPath(own)) {
		return "", errors.New("that is where this conversation is kept, which the tools do not touch")
	}
	return p, nil
}

// realPath is where p really leads: its deepest part that exists, with every
// link in it followed, and the rest of p after it.
func realPath(p string) string {
	rest := ""
	for dir := p; ; {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// within reports whether p is dir or inside it, ignoring case where the file
// system usually does (macOS, Windows).
func within(p, dir string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// cut is s within n bytes: its start and end, saying how much was left out.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	head, tail := n/3, n-n/3
	return s[:head] + fmt.Sprintf("\n\n[… %d bytes left out …]\n\n", len(s)-head-tail) + s[len(s)-tail:]
}

// commandEnv is a command's environment: the loop's own, without what only
// the loop uses, and saying nothing can answer a prompt.
func commandEnv() []string {
	var out []string
	set := append([]string{"GIT_TERMINAL_PROMPT", "PAGER", "GIT_PAGER", "DEBIAN_FRONTEND"}, loopEnv...)
next:
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		for _, n := range set {
			// Windows' names are the same whatever their case.
			if name == n || runtime.GOOS == "windows" && strings.EqualFold(name, n) {
				continue next
			}
		}
		out = append(out, kv)
	}
	return append(out, "GIT_TERMINAL_PROMPT=0", "PAGER=cat", "GIT_PAGER=cat", "DEBIAN_FRONTEND=noninteractive")
}

// keptOutput keeps the first commandKept bytes written to it, and counts the
// rest.
type keptOutput struct {
	b       bytes.Buffer
	dropped int
}

func (k *keptOutput) Write(p []byte) (int, error) {
	room := commandKept - k.b.Len()
	if room >= len(p) {
		k.b.Write(p)
	} else {
		if room > 0 {
			k.b.Write(p[:room])
		}
		k.dropped += len(p) - max(room, 0)
	}
	return len(p), nil
}

// run runs a command in the system shell, in its own process group, ended
// whole when the command ends or runs out of time.
func (w workTools) run(ctx context.Context, command string, seconds int) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", errors.New("name a command to run")
	}
	wait := commandWait
	if seconds > 0 {
		wait = time.Duration(seconds) * time.Second
	}
	if wait > commandWaitLongest {
		wait = commandWaitLongest
	}
	cctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	cmd.Dir, cmd.Env, cmd.Stdin = w.dir, commandEnv(), nil
	var out keptOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	ownGroup(cmd)
	// What it left running may hold its output open: the output stops being
	// read soon after the command itself ends.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("the command could not be started: %v", err)
	}
	group := groupOf(cmd)
	defer group.close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	timedOut := false
	select {
	case err = <-done:
	case <-cctx.Done():
		timedOut = true
		group.end()
		err = <-done
	}
	// Whatever it left running is ended with it.
	group.end()
	text := out.b.String()
	if out.dropped > 0 {
		text += fmt.Sprintf("\n[… %d more bytes were printed and not kept …]", out.dropped)
	}
	status := "exit status 0"
	var ee *exec.ExitError
	switch {
	case timedOut && ctx.Err() != nil:
		status = "stopped: the turn ran out of time"
	case timedOut:
		status = fmt.Sprintf("stopped after %s, still running", wait)
	case errors.As(err, &ee):
		status = "exit status " + fmt.Sprint(ee.ExitCode())
	case err != nil:
		status = err.Error()
	}
	return cut(status+"\n"+text, toolShown), nil
}

// regularFile opens p for reading only if it is a regular file.
func regularFile(p string) (*os.File, os.FileInfo, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	return f, fi, nil
}

// binary reports whether b looks like binary data rather than text.
func binary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}

func (w workTools) read(path string, offset, limit int) (string, error) {
	p, err := w.path(path)
	if err != nil {
		return "", err
	}
	f, _, err := regularFile(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if offset < 1 {
		offset = 1
	}
	if limit <= 0 || limit > readLines {
		limit = readLines
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var b strings.Builder
	line, shown := 0, 0
	more := false
	for {
		s, err := r.ReadString('\n')
		if s != "" {
			line++
			if line == 1 && binary([]byte(s)) {
				return "", fmt.Errorf("%s holds binary data, not text", p)
			}
			if line >= offset {
				if shown == limit || b.Len()+len(s) > readLargest {
					more = true
					break
				}
				fmt.Fprintf(&b, "%6d\t%s", line, strings.TrimRight(s, "\n")+"\n")
				shown++
			}
		}
		if err != nil {
			break
		}
	}
	if shown == 0 {
		if line == 0 {
			return "(the file is empty)", nil
		}
		return fmt.Sprintf("(the file has %d lines; none from line %d)", line, offset), nil
	}
	if more {
		fmt.Fprintf(&b, "[… more follows; read on from line %d …]\n", offset+shown)
	}
	return b.String(), nil
}

func (w workTools) write(path, content string) (string, error) {
	p, err := w.path(path)
	if err != nil {
		return "", err
	}
	mode := fs.FileMode(0o644)
	if fi, err := os.Stat(p); err == nil {
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s is not a regular file", p)
		}
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote %d bytes to %s.", len(content), p), nil
}

func (w workTools) replace(path, old, new string, all bool) (string, error) {
	if old == "" {
		return "", errors.New("old_text is empty; to write a whole file, use write_file")
	}
	p, err := w.path(path)
	if err != nil {
		return "", err
	}
	f, fi, err := regularFile(p)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return "", err
	}
	n := strings.Count(string(b), old)
	switch {
	case n == 0:
		return "", fmt.Errorf("old_text does not occur in %s; read the file and copy the text exactly", p)
	case n > 1 && !all:
		return "", fmt.Errorf("old_text occurs %d times in %s; give more of the text around it, or set replace_all", n, p)
	}
	s := strings.Replace(string(b), old, new, -1)
	if err := os.WriteFile(p, []byte(s), fi.Mode().Perm()); err != nil {
		return "", err
	}
	return fmt.Sprintf("Replaced %d occurrence(s) in %s.", n, p), nil
}

// walk calls each for every regular file under root, in order, passing over
// skipped folders, until each says to stop.
func (w workTools) walk(ctx context.Context, root string, each func(path, rel string, d fs.DirEntry) bool) error {
	stop := errors.New("stop")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			// A turn asked to stop stops here, so its conversation is kept.
			return ctx.Err()
		}
		if err != nil {
			if p == root {
				return err
			}
			return nil // a folder it may not read is passed over
		}
		if d.IsDir() {
			if p != root && skipped[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if !each(p, rel, d) {
			return stop
		}
		return nil
	})
	if errors.Is(err, stop) {
		return nil
	}
	return err
}

// matches reports whether a file's name, or its path from where the search
// began, matches pattern.
func matches(pattern, rel string) bool {
	if pattern == "" {
		return true
	}
	if ok, _ := filepath.Match(pattern, filepath.Base(rel)); ok {
		return true
	}
	ok, _ := filepath.Match(pattern, filepath.ToSlash(rel))
	return ok
}

func (w workTools) list(ctx context.Context, path, pattern string) (string, error) {
	if path == "" {
		path = "."
	}
	root, err := w.path(path)
	if err != nil {
		return "", err
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return "", fmt.Errorf("the pattern is not one a name can match: %v", err)
	}
	var names []string
	more := false
	err = w.walk(ctx, root, func(p, rel string, d fs.DirEntry) bool {
		if !matches(pattern, rel) {
			return true
		}
		if len(names) == listMost {
			more = true
			return false
		}
		names = append(names, filepath.ToSlash(rel))
		return true
	})
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "(no files)", nil
	}
	out := strings.Join(names, "\n")
	if more {
		out += fmt.Sprintf("\n[… more than %d files; name a folder or a pattern …]", listMost)
	}
	return cut(out, toolShown), nil
}

func (w workTools) search(ctx context.Context, path, expr, pattern string) (string, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return "", fmt.Errorf("the regular expression does not compile: %v", err)
	}
	if path == "" {
		path = "."
	}
	root, err := w.path(path)
	if err != nil {
		return "", err
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return "", fmt.Errorf("the pattern is not one a name can match: %v", err)
	}
	var b strings.Builder
	found := 0
	more := false
	err = w.walk(ctx, root, func(p, rel string, d fs.DirEntry) bool {
		if !matches(pattern, rel) {
			return true
		}
		if fi, err := d.Info(); err != nil || fi.Size() > searchFileLargest {
			return true
		}
		data, err := os.ReadFile(p)
		if err != nil || binary(data) {
			return true
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !re.MatchString(line) {
				continue
			}
			if found == searchMost {
				more = true
				return false
			}
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			fmt.Fprintf(&b, "%s:%d: %s\n", filepath.ToSlash(rel), i+1, line)
			found++
		}
		return true
	})
	if err != nil {
		return "", err
	}
	if found == 0 {
		return "(nothing matches)", nil
	}
	if more {
		fmt.Fprintf(&b, "[… more than %d matches; narrow the search …]\n", searchMost)
	}
	return cut(b.String(), toolShown), nil
}
