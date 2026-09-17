package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const chunkSize = 32 * 1024

type RequestFrame struct {
	T        string            `json:"t"`
	StreamID string            `json:"stream_id"`
	RAID     string            `json:"raid"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	BodyB64  *string           `json:"body_b64"`
}

type ResponseFrame struct {
	T        string            `json:"t"`
	StreamID string            `json:"stream_id"`
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	BodyB64  string            `json:"body_b64,omitempty"`
	Final    bool              `json:"final,omitempty"`
	Seq      int               `json:"seq,omitempty"`
}

// TunnelAgent maintains the outbound WSS and serves framed inbound requests (the contract §4).
type TunnelAgent struct {
	Endpoint   string
	Token      string
	LocalBase  string
	HTTPClient *http.Client
	dialer     websocket.Dialer
	mu         sync.Mutex
	conn       *websocket.Conn

	// onConnect fires once the socket is up, before any request is served.
	// Without it a caller cannot distinguish "dialing" from "connected" — it
	// only learns of a session when the session ENDS, which is too late to
	// report that reachability was restored.
	onConnect func()
}

func NewTunnelAgent(endpoint, token, localBase string) *TunnelAgent {
	return &TunnelAgent{
		Endpoint: endpoint, Token: token, LocalBase: strings.TrimRight(localBase, "/"),
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (a *TunnelAgent) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := a.session(ctx); err != nil && ctx.Err() == nil {
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff = backoff * 2
			}
			continue
		}
		return ctx.Err()
	}
}

func (a *TunnelAgent) session(ctx context.Context) error {
	hdr := http.Header{}
	hdr.Set("Authorization", a.Token)
	conn, _, err := a.dialer.DialContext(ctx, a.Endpoint, hdr)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.conn = conn
	cb := a.onConnect
	a.mu.Unlock()
	defer conn.Close()
	if cb != nil {
		cb()
	}
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var kind struct {
			T string `json:"t"`
		}
		if json.Unmarshal(msg, &kind) != nil {
			continue
		}
		switch kind.T {
		case "req":
			var req RequestFrame
			if json.Unmarshal(msg, &req) == nil {
				go a.handleRequest(conn, req)
			}
		case "ping":
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"t":"pong"}`))
		}
	}
}

// newForwardRequest builds the HTTP request the box serves for an inbound relay
// frame. It stamps the ingress marker so a relay-forwarded request — which
// reaches the box over loopback — is never mistaken for the genuinely-local
// owner (see the header note below).
func (a *TunnelAgent) newForwardRequest(req RequestFrame) (*http.Request, error) {
	// Carry the request body. The inbound frame delivers it base64-encoded;
	// forwarding it with a nil body (as this once did) meant a signed POST — a
	// controller grant, a rotation, any owner/controller action — reached the box
	// with an empty body and failed signature verification, so nothing but GETs
	// worked over the relay.
	var body io.Reader
	if req.BodyB64 != nil && *req.BodyB64 != "" {
		raw, err := base64.RawURLEncoding.DecodeString(*req.BodyB64)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	httpReq, err := http.NewRequest(req.Method, a.LocalBase+req.Path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	// The agent treats a loopback request with no forwarding marker as its
	// genuinely-local owner (isLocalOwnerRequest), and a relay-forwarded request
	// also arrives over loopback — so without this, anyone who learned the relay
	// URL would be the owner, with no signature required. Set here on the box,
	// after the client's headers are applied, so a client can neither remove nor
	// preempt it; a client that adds a forwarding header of its own only marks
	// itself more remote, never less.
	httpReq.Header.Set("X-IA-Via-Ingress", "relay")
	return httpReq, nil
}

func (a *TunnelAgent) handleRequest(conn *websocket.Conn, req RequestFrame) {
	httpReq, err := a.newForwardRequest(req)
	if err != nil {
		a.writeErr(conn, req.StreamID, err)
		return
	}
	resp, err := a.HTTPClient.Do(httpReq)
	if err != nil {
		a.writeErr(conn, req.StreamID, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	headers := map[string]string{}
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	if len(body) <= chunkSize {
		frame := ResponseFrame{
			T: "res", StreamID: req.StreamID, Status: resp.StatusCode,
			Headers: headers, BodyB64: base64.RawURLEncoding.EncodeToString(body), Final: true,
		}
		raw, _ := json.Marshal(frame)
		_ = conn.WriteMessage(websocket.TextMessage, raw)
		return
	}
	seq := 0
	for off := 0; off < len(body); off += chunkSize {
		end := off + chunkSize
		if end > len(body) {
			end = len(body)
		}
		chunk := body[off:end]
		final := end == len(body)
		frame := ResponseFrame{
			T: "res_chunk", StreamID: req.StreamID, Status: resp.StatusCode,
			Headers: headers, BodyB64: base64.RawURLEncoding.EncodeToString(chunk),
			Seq: seq, Final: final,
		}
		if seq == 0 {
			frame.T = "res_chunk"
		}
		raw, _ := json.Marshal(frame)
		_ = conn.WriteMessage(websocket.TextMessage, raw)
		seq++
	}
}

func (a *TunnelAgent) writeErr(conn *websocket.Conn, streamID string, err error) {
	raw, _ := json.Marshal(map[string]string{"t": "err", "stream_id": streamID, "code": "agent_error", "detail": err.Error()})
	_ = conn.WriteMessage(websocket.TextMessage, raw)
}
