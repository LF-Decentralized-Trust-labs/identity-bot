package server

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Serving the web UI from somewhere other than the root of a domain.
//
// A Flutter web build hard-codes where it expects to live. index.html carries a
// <base href="..."> and every other file — main.dart.js, the asset manifest,
// canvaskit — is fetched relative to it. Built for the root, that base is "/".
//
// An agent reached directly on its own port is at the root, so this never came
// up. An agent reached through a relay is not: it lives under a path the relay
// assigned, and the browser is looking at something like
// https://host/some-prefix/. It loads index.html fine, reads <base href="/">,
// and then asks for /main.dart.js — which is not where the app is. The result
// is a blank page, because the shell loaded and the code never did.
//
// Two halves, and both are needed because a relay may forward the prefix or
// strip it, and the agent cannot assume which:
//
//   - The base href in index.html is rewritten to the prefix actually in use,
//     so the browser asks for the right URLs.
//   - The prefix is stripped from incoming paths before looking for a file, so
//     a request that arrives still carrying it finds the file anyway.
//
// The prefix is discovered, not configured, wherever possible. A proxy that
// knows it is serving a subpath is the only party that reliably does; asking an
// operator to keep an environment variable in step with the relay's routing is
// asking for a mismatch nobody notices until the page is blank.

// baseHrefPattern matches the base tag Flutter emits. Deliberately narrow: it
// rewrites the href of a <base> tag and nothing else, so a stray href elsewhere
// in the document is untouched.
var baseHrefPattern = regexp.MustCompile(`(?i)(<base\s+href=")([^"]*)(")`)

// webPathPrefix reports the path this agent is being served under, as a prefix
// with a leading and trailing slash ("/" when at the root).
//
// X-Forwarded-Prefix is preferred because the proxy is the only party that
// actually knows. WEB_BASE_HREF exists for deployments whose proxy does not set
// it, and is a fallback rather than the primary answer: a static setting has to
// be kept in step with routing by hand, which is exactly the kind of agreement
// that quietly stops being true.
func webPathPrefix(r *http.Request) string {
	prefix := r.Header.Get("X-Forwarded-Prefix")
	if prefix == "" {
		prefix = os.Getenv("WEB_BASE_HREF")
	}
	return normalisePrefix(prefix)
}

// normalisePrefix turns anything a proxy might send into a form the browser can
// use as a base: exactly one leading slash, exactly one trailing slash.
//
// A base href without a trailing slash is the classic version of this bug: the
// browser treats the last segment as a file and resolves siblings against its
// parent, so "/app" makes main.dart.js load from "/" and the page is blank
// again for a reason that looks nothing like the cause.
func normalisePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return "/"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix
}

// stripPrefix removes the serving prefix from a request path, so a file lookup
// works whether or not the proxy stripped it first.
//
// Being tolerant here is deliberate. Whether a relay forwards the prefix is a
// property of somebody else's configuration, and an agent that only worked one
// way would fail with the same blank page and no clue which half was wrong.
func stripPrefix(urlPath, prefix string) string {
	if prefix == "/" || prefix == "" {
		return urlPath
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	if urlPath == trimmed {
		return "/"
	}
	if strings.HasPrefix(urlPath, prefix) {
		return "/" + strings.TrimPrefix(urlPath, prefix)
	}
	return urlPath
}

// serveShell writes index.html with its base href set to the prefix in use.
//
// Read and rewritten per request rather than cached. It is one small file, it
// is already served no-cache because its name is stable, and a cache keyed on
// nothing would serve one deployment's prefix to another.
func serveShell(w http.ResponseWriter, indexPath, prefix string) {
	html, err := os.ReadFile(indexPath)
	if err != nil {
		http.Error(w, "web UI is not available", http.StatusNotFound)
		return
	}

	if prefix != "/" {
		replaced := baseHrefPattern.ReplaceAll(html, []byte("${1}"+prefix+"${3}"))
		if !bytes.Equal(replaced, html) {
			html = replaced
		} else {
			// No <base> tag to rewrite. Say so rather than serving a shell that
			// will silently fetch from the wrong place — a blank page with a
			// clean log is the hardest version of this to diagnose.
			log.Printf("[web] serving under %s but index.html has no <base href> to rewrite; "+
				"the app will fetch its code from the wrong path and render blank", prefix)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(html)
}
