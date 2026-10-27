package agenthost

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeHomeBrain is a stand-in for Codex or Grok that writes down its
// arguments, the home it was given, the sign-in file it found there, and
// whether the wrapper's own variable reached it; then renews the sign-in file
// if asked, and answers or fails.
func fakeHomeBrain(t *testing.T, homeVar, output string, renew, fail bool) (path, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	path = filepath.Join(dir, "brain")
	script := "#!/bin/sh\ncat >/dev/null\nfor a in \"$@\"; do printf 'ARG:%s\\n' \"$a\" >> " + record + "; done\n" +
		"printf 'HOME:%s\\n' \"$" + homeVar + "\" >> " + record + "\n" +
		"printf 'FILE:%s\\n' \"$(cat \"$" + homeVar + "/auth.json\" 2>/dev/null)\" >> " + record + "\n" +
		"printf 'CONFIG:%s\\n' \"$(cat \"$" + homeVar + "/config.toml\" | tr '\\n' '|')\" >> " + record + "\n" +
		"printf 'SPEC:%s\\n' \"$" + envBrainHome + "\" >> " + record + "\n" +
		"printf 'MODELKEY:%s\\n' \"$" + envModelKey + "\" >> " + record + "\n"
	if renew {
		script += "printf '%s' '{\"renewed\":true}' > \"$" + homeVar + "/auth.json\"\n"
	}
	if fail {
		script += "echo 'usage limit reached' >&2\nexit 3\n"
	} else {
		script += "cat <<'OUT'\n" + output + "\nOUT\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

const codexAnswer = `{"type":"thread.started","thread_id":"thread-7"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"i0","type":"agent_message","text":"Done."}}
{"type":"turn.completed","usage":{"input_tokens":1}}`

// A Codex sign-in is a file in the run's home for that run alone: Codex finds
// it there, nothing of it is on the command line, it is gone when the run
// ends — also when the run fails — and a file Codex renewed comes back so the
// Identity Agent can keep it. Before, a Codex sign-in could not be run at all.
func TestACodexSignInIsAFileForOneRun(t *testing.T) {
	const signIn = `{"tokens":{"access_token":"A-CODEX-ACCESS-TOKEN","refresh_token":"R1"}}`
	for _, c := range []struct{ renew, fail bool }{{false, false}, {true, false}, {true, true}} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		path, record := fakeHomeBrain(t, "CODEX_HOME", codexAnswer, c.renew, c.fail)
		b := Borrowed{Kind: "subscription", Provider: "codex", secret: signIn}
		env, err := b.Env("codex")
		if err != nil {
			t.Fatal(err)
		}
		workspace := t.TempDir()
		out, err := Codex{Path: path}.Run(context.Background(), Turn{Session: "ours", Prompt: "hello",
			Workspace: workspace, ToolsURL: "http://127.0.0.1:1", ToolsToken: "tt", Credentials: env})
		if c.fail {
			if err == nil || !strings.Contains(err.Error(), "usage limit reached") || strings.Contains(err.Error(), "R1") {
				t.Fatalf("a failed run: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(record)
		rec := string(got)
		brainHome := filepath.Join(home, ".agent-host-brain", homeName("codex", ""))
		if !strings.Contains(rec, "HOME:"+brainHome+"\n") || !strings.Contains(rec, "FILE:"+signIn+"\n") {
			t.Fatalf("Codex did not find the sign-in in its home:\n%s", rec)
		}
		if !strings.Contains(rec, "SPEC:\n") {
			t.Fatalf("the wrapper's variable, which carries the sign-in, reached Codex:\n%s", rec)
		}
		for _, l := range strings.Split(rec, "\n") {
			if strings.HasPrefix(l, "ARG:") && strings.Contains(l, "CODEX-ACCESS") {
				t.Fatalf("the sign-in went on the command line: %s", l)
			}
		}
		if !strings.Contains(rec, "ARG:--ignore-user-config\n") || !strings.Contains(rec, `ARG:cli_auth_credentials_store="file"`) {
			t.Fatalf("Codex could read its user's own settings, or its keyring:\n%s", rec)
		}
		if _, err := os.Stat(filepath.Join(brainHome, "auth.json")); !os.IsNotExist(err) {
			t.Fatalf("renew=%v fail=%v: the sign-in file is still in the brain's home", c.renew, c.fail)
		}
		noFileUnder(t, workspace, "CODEX-ACCESS")
		noFileUnder(t, home, "CODEX-ACCESS")
		switch {
		case c.renew && out.refreshed != `{"renewed":true}`:
			t.Fatalf("the renewed sign-in did not come back: %q", out.refreshed)
		case !c.renew && out.refreshed != "":
			t.Fatalf("an unchanged sign-in came back as renewed")
		}
		if !c.fail && (out.Text != "Done." || out.Brain.Session != "thread-7") {
			t.Fatalf("Codex's answer was not read: %+v", out)
		}
	}
}

// A later turn resumes the session Codex started.
func TestCodexResumesTheSessionItStarted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, record := fakeHomeBrain(t, "CODEX_HOME", codexAnswer, false, false)
	if _, err := (Codex{Path: path}).Run(context.Background(), Turn{Session: "thread-7", Resume: true, Prompt: "again",
		Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(record)
	if !strings.Contains(string(got), "ARG:resume\n") || !strings.Contains(string(got), "ARG:thread-7\nARG:-\n") {
		t.Fatalf("not resumed:\n%s", got)
	}
}

// isolatedSameUser is SameUser that says it is isolated, as AsUser is, so a
// test can run Grok.
type isolatedSameUser struct{ SameUser }

func (isolatedSameUser) Isolated() bool { return true }

// A model at OpenRouter's address is reached through Grok's settings in the
// run's home, which name the variable holding the key and never the key.
func TestGrokReachesOpenRouterWithTheKeyOnlyInItsEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const key = "sk-or-v1-AN-OPENROUTER-KEY"
	path, record := fakeHomeBrain(t, "GROK_HOME", `{"text":"hi","sessionId":"ours","modelUsage":{}}`, false, false)
	b := Borrowed{Kind: "api_key", Provider: "openrouter", secret: key}
	env, err := b.Env("grok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (GrokCLI{Path: path, Runner: isolatedSameUser{}}).Run(context.Background(), Turn{Session: "ours",
		Prompt: "hello", Workspace: t.TempDir(), Credentials: env}); err == nil || !strings.Contains(err.Error(), "name of the model") {
		t.Fatalf("a model server with no model named: %v", err)
	}
	out, err := GrokCLI{Path: path, Runner: isolatedSameUser{}}.Run(context.Background(), Turn{Session: "ours",
		Prompt: "hello", Workspace: t.TempDir(), Credentials: env, Model: "anthropic/claude-sonnet-4.5"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(record)
	rec := string(got)
	if !strings.Contains(rec, "MODELKEY:"+key+"\n") {
		t.Fatalf("Grok was not given the key:\n%s", rec)
	}
	if !strings.Contains(rec, `base_url = "https://openrouter.ai/api/v1"`) || !strings.Contains(rec, `env_key = "`+envModelKey+`"`) ||
		!strings.Contains(rec, `model = "anthropic/claude-sonnet-4.5"`) || !strings.Contains(rec, "ARG:"+grokModelName+"\n") {
		t.Fatalf("Grok's settings do not name the model at OpenRouter:\n%s", rec)
	}
	noFileUnder(t, home, key)
	if out.Text != "hi" {
		t.Fatalf("Grok's answer was not read: %+v", out)
	}
}

// A sign-in file a crashed run left behind is gone before the next run uses
// the home.
func TestASignInLeftByACrashIsRemoved(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".agent-host-brain", homeName("grok", ""))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), []byte("LEFT-BY-A-CRASH"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, record := fakeHomeBrain(t, "GROK_HOME", `{"text":"hi","sessionId":"s","modelUsage":{}}`, false, false)
	env, _ := (&Borrowed{Kind: "api_key", Provider: "xai", secret: "xk"}).Env("grok")
	if _, err := (GrokCLI{Path: path, Runner: isolatedSameUser{}}).Run(context.Background(), Turn{Session: "s",
		Prompt: "hello", Workspace: t.TempDir(), Credentials: env}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(record)
	if !strings.Contains(string(got), "FILE:\n") {
		t.Fatalf("the brain found a sign-in left by an earlier run:\n%s", got)
	}
	noFileUnder(t, home, "LEFT-BY-A-CRASH")
}

func noFileUnder(t *testing.T, dir, secret string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), secret) {
			t.Errorf("%s holds the secret", p)
		}
		return nil
	})
}

// Each AI agent's brain has a home of its own, which only the brain's user can
// open, so one AI agent's run does not find another's sessions there. A
// sign-in a killed run left in the home every AI agent once shared is removed.
// Before, every AI agent running Codex on a machine shared one home.
func TestEachAIAgentHasAHomeOfItsOwn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacy := filepath.Join(home, ".agent-host-brain", "codex")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "auth.json"), []byte("LEFT-IN-THE-SHARED-HOME"), 0o600); err != nil {
		t.Fatal(err)
	}
	var homes []string
	for _, agent := range []string{"EAgentOne", "EAgentTwo"} {
		path, record := fakeHomeBrain(t, "CODEX_HOME", codexAnswer, false, false)
		env, err := (&Borrowed{Kind: "subscription", Provider: "codex", secret: `{"tokens":{"refresh_token":"R"}}`,
			agent: agent}).Env("codex")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (Codex{Path: path}).Run(context.Background(), Turn{Session: "s", Prompt: "hi",
			Workspace: t.TempDir(), Credentials: env}); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(record)
		for _, l := range strings.Split(string(got), "\n") {
			if h, ok := strings.CutPrefix(l, "HOME:"); ok {
				homes = append(homes, h)
			}
		}
	}
	if len(homes) != 2 || homes[0] == homes[1] || homes[0] == legacy {
		t.Fatalf("two AI agents' homes: %v", homes)
	}
	for _, h := range append(homes, filepath.Dir(homes[0])) {
		if st, err := os.Stat(h); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s is not the brain user's alone: %v %v", h, st.Mode(), err)
		}
	}
	noFileUnder(t, home, "LEFT-IN-THE-SHARED-HOME")
}

// A renewed sign-in that cannot be given back stays with the borrowed one
// until it can; once every try has failed it is kept on this machine, in the
// host's own directory and readable by it alone, for the next time the
// Identity Agent can be reached.
func TestARenewedSignInThatCannotBeGivenBackIsKept(t *testing.T) {
	saved := returnBackoff
	returnBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { returnBackoff = saved })
	h := &Host{DataDir: t.TempDir()} // never enrolled: nothing can be returned
	b := &Borrowed{LeaseID: "bl_1", secret: "S", refreshed: "RENEWED-SIGN-IN"}
	if err := h.Return(context.Background(), b); err == nil || b.refreshed != "RENEWED-SIGN-IN" || b.secret != "" {
		t.Fatalf("a failed return: %v, refreshed %q", err, b.refreshed)
	}
	h.giveBack(b, func(string, ...any) {})
	if b.refreshed != "" {
		t.Fatal("the renewed sign-in is still held by the run")
	}
	p := filepath.Join(h.DataDir, "sign-ins-to-give-back.json")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the renewed sign-in was not kept to give back: %v %v", st, err)
	}
	if got := h.loadPendingReturns(); len(got) != 1 || got[0].LeaseID != "bl_1" || got[0].SignIn != "RENEWED-SIGN-IN" {
		t.Fatalf("kept to give back: %+v", got)
	}
	// Still out of reach: it stays.
	h.givePendingBack(context.Background(), func(string, ...any) {})
	if len(h.loadPendingReturns()) != 1 {
		t.Fatal("a renewed sign-in was dropped while the Identity Agent could not be reached")
	}
}
