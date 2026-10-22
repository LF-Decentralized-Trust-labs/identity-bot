package relayproto

import (
	"html/template"
	"net/http"
	"net/url"
)

// DefaultVisitorLink is where the visitor page points when the relay's
// operator names nowhere else: the open-source Identity Agent.
const DefaultVisitorLink = "https://github.com/LF-Decentralized-Trust-labs/identity-bot"

var visitorPage = template.Must(template.New("visitor").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Identity Agent address</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;color:#222}</style>
</head><body>
<p>This is the address of an Identity Agent. It is reached by Identity Agents, not by web browsers.</p>
<p>To connect with whoever is here, <a href="{{.}}" rel="noopener noreferrer">get an Identity Agent</a> and give it this page's address.</p>
</body></html>
`))

// ServeVisitorPage answers a browser that loads a page at a relay address.
// The page is the relay's own and the same at every address: it says what the
// address is and where to get an Identity Agent, and it carries nothing an
// Identity Agent sent. link is the operator's choice of where "get an Identity
// Agent" leads; an empty or non-https link means DefaultVisitorLink.
func ServeVisitorPage(w http.ResponseWriter, r *http.Request, link string) {
	if u, err := url.Parse(link); err != nil || u.Scheme != "https" || u.Host == "" {
		link = DefaultVisitorLink
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	// Never cached: the same URL answers an Identity Agent with protocol data,
	// and a cache in front must not hand this page to it, or that data to a
	// browser.
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Sec-Fetch-Mode, Sec-Fetch-Dest, Accept")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = visitorPage.Execute(w, link)
}
