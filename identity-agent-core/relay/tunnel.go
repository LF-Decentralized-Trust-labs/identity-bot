package relay

import (
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
	a.mu.Unlock()
	defer conn.Close()
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

func (a *TunnelAgent) handleRequest(conn *websocket.Conn, req RequestFrame) {
	target := a.LocalBase + req.Path
	httpReq, err := http.NewRequest(req.Method, target, nil)
	if err != nil {
		a.writeErr(conn, req.StreamID, err)
		return
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
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