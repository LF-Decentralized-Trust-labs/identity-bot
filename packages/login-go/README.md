# login-go

Sign a person in through their Identity Agent from a Go back end. This is the Go
half of `startLoginSession` and `confirmLoginSession` in
`@identity-agent/login-web/server`; standard library only.

```go
import login "github.com/LF-Decentralized-Trust-labs/identity-bot/packages/login-go"

agent := login.HTTPAgent{URL: agentURL, AssetID: assetID}

// 1. The person asks to sign in. Show them s.PointerUrl; keep s.CollectorSecret on the server.
s, err := login.StartSession(ctx, agent, login.StartRequest{
	Audience: "https://your-site.example",
	BrowserKey: thumbprint, FrontEnd: login.FrontEndBrowser, // for a utility app's browser page
})

// 2. When the page asks how it went:
c, err := login.ConfirmSession(ctx, agent, login.ConfirmOptions{
	SessionToken: s.SessionToken, CollectorSecret: s.CollectorSecret,
	Spent: spent, // login.InMemorySpent, or your own shared store
})
if c.State == login.Verified { issueYourSession(c.PairwiseAID, c.BrowserKey) }
```

`HTTPAgent` reaches the Identity Agent's public login routes, which is what a
site's own back end uses. `Agent` is the seam for any other transport: a utility
app's machine reaches its Identity Agent by sealed, app-signed calls, supplies an
`Agent` that makes them, and gets the same checks (an answer without a secret is
refused, verified with no identity is pending, a withheld identity is an error,
a verified sign-in is spent once) without writing any.

Issue your own session only on `Verified`. `Spent` makes a verified sign-in sign
nobody in a second time; a site that restarts or runs more than one process
supplies a store they share. The front-end kind is named in the challenge the
Identity Agent signs, and the Identity Agent refuses a kind the app's owner has
switched off (ADR-072 Amendment 2).

The request each call makes and what it does with each answer are the cases in
`packages/login-web/test-vectors/start-and-confirm.json`. The TypeScript package
and this one both read that file, so they cannot drift apart: change a case
there, and both tests say which side disagrees.

## Sealed front-end traffic

`seal.go` is what a utility app's back end uses to open the calls its page seals and to
seal its answers (ADR-072 Amendment 4): `SealKeyFromSeed`, `SealKey.OpenRequest`,
`Reply.Seal`, and `SealKeyStatement` for the `seal` part of the sign-in link. It is held
to `packages/login-web/test-vectors/seal.json`, the same file the page's TypeScript is.
