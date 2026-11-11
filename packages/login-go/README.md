# login-go

Sign a person in through their Identity Agent from a Go back end. This is the Go
half of `startLoginSession` and `confirmLoginSession` in
`@identity-agent/login-web/server`; standard library only.

```go
import login "github.com/LF-Decentralized-Trust-labs/identity-bot/packages/login-go"

// 1. The person asks to sign in. Show them s.PointerUrl; keep s.CollectorSecret on the server.
s, err := login.StartSession(ctx, login.StartOptions{
	AgentURL: agentURL, AssetID: assetID, Audience: "https://your-site.example",
	BrowserKey: thumbprint, FrontEnd: login.FrontEndBrowser, // for a utility app's browser page
})

// 2. When the page asks how it went:
c, err := login.ConfirmSession(ctx, login.ConfirmOptions{
	AgentURL: agentURL, AssetID: assetID, SessionToken: s.SessionToken,
	CollectorSecret: s.CollectorSecret, Spent: spent, // login.InMemorySpent, or your own shared store
})
if c.State == login.Verified { issueYourSession(c.PairwiseAID) }
```

Issue your own session only on `Verified`. `Spent` makes a verified sign-in sign
nobody in a second time; a site that restarts or runs more than one process
supplies a store they share. The front-end kind is named in the challenge the
Identity Agent signs, and the Identity Agent refuses a kind the app's owner has
switched off (ADR-072 Amendment 2).

The request each call makes and what it does with each answer are the cases in
`packages/login-web/test-vectors/start-and-confirm.json`. The TypeScript package
and this one both read that file, so they cannot drift apart: change a case
there, and both tests say which side disagrees.
