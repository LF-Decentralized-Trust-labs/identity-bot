package sandbox

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type TraceEntry struct {
	ID        int64                  `json:"id"`
	TraceID   string                 `json:"trace_id"`
	Timestamp time.Time              `json:"timestamp"`
	Module    string                 `json:"module"`
	Stage     string                 `json:"stage"`
	Direction string                 `json:"direction"`
	AppID     string                 `json:"app_id"`
	Instance  string                 `json:"instance_id"`
	Summary   string                 `json:"summary"`
	Detail    map[string]interface{} `json:"detail,omitempty"`
	Duration  time.Duration          `json:"duration_ns"`
	Seq       int                    `json:"seq"`
}

type TraceSession struct {
	TraceID     string       `json:"trace_id"`
	AppID       string       `json:"app_id"`
	InstanceID  string       `json:"instance_id"`
	StartedAt   time.Time    `json:"started_at"`
	Status      string       `json:"status"`
	Entries     []TraceEntry `json:"entries"`
	StepThrough bool         `json:"step_through"`
	entrySeq    int
	mu          sync.Mutex
}

type Tracer struct {
	enabled     atomic.Bool
	stepMode    atomic.Bool
	sessions    map[string]*TraceSession
	ringBuffer  []TraceEntry
	ringPos     int
	ringSize    int
	entryIDSeq  atomic.Int64
	subscribers map[string]chan TraceEntry
	pauseCh     map[string]chan struct{}
	mu          sync.RWMutex
}

func NewTracer(ringSize int) *Tracer {
	if ringSize <= 0 {
		ringSize = 2000
	}
	return &Tracer{
		sessions:    make(map[string]*TraceSession),
		ringBuffer:  make([]TraceEntry, 0, ringSize),
		ringSize:    ringSize,
		subscribers: make(map[string]chan TraceEntry),
		pauseCh:     make(map[string]chan struct{}),
	}
}

func (t *Tracer) SetEnabled(enabled bool) {
	t.enabled.Store(enabled)
}

func (t *Tracer) IsEnabled() bool {
	return t.enabled.Load()
}

func (t *Tracer) SetStepMode(enabled bool) {
	t.stepMode.Store(enabled)
}

func (t *Tracer) IsStepMode() bool {
	return t.stepMode.Load()
}

func (t *Tracer) StartSession(appID, instanceID string, stepThrough bool) string {
	traceID := fmt.Sprintf("trace-%s-%d", appID, time.Now().UnixMilli())

	session := &TraceSession{
		TraceID:     traceID,
		AppID:       appID,
		InstanceID:  instanceID,
		StartedAt:   time.Now(),
		Status:      "active",
		Entries:     []TraceEntry{},
		StepThrough: stepThrough,
	}

	t.mu.Lock()
	t.sessions[traceID] = session
	if stepThrough {
		t.pauseCh[traceID] = make(chan struct{}, 1)
	}
	t.mu.Unlock()

	return traceID
}

func (t *Tracer) EndSession(traceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.sessions[traceID]; ok {
		s.mu.Lock()
		s.Status = "completed"
		s.mu.Unlock()
	}
	if ch, ok := t.pauseCh[traceID]; ok {
		close(ch)
		delete(t.pauseCh, traceID)
	}
}

func (t *Tracer) GetSession(traceID string) *TraceSession {
	t.mu.RLock()
	s, ok := t.sessions[traceID]
	t.mu.RUnlock()
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := &TraceSession{
		TraceID:     s.TraceID,
		AppID:       s.AppID,
		InstanceID:  s.InstanceID,
		StartedAt:   s.StartedAt,
		Status:      s.Status,
		StepThrough: s.StepThrough,
		entrySeq:    s.entrySeq,
	}
	snapshot.Entries = make([]TraceEntry, len(s.Entries))
	copy(snapshot.Entries, s.Entries)
	return snapshot
}

func (t *Tracer) ListSessions() []*TraceSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]*TraceSession, 0, len(t.sessions))
	for _, s := range t.sessions {
		s.mu.Lock()
		snapshot := &TraceSession{
			TraceID:     s.TraceID,
			AppID:       s.AppID,
			InstanceID:  s.InstanceID,
			StartedAt:   s.StartedAt,
			Status:      s.Status,
			StepThrough: s.StepThrough,
			entrySeq:    s.entrySeq,
		}
		snapshot.Entries = make([]TraceEntry, len(s.Entries))
		copy(snapshot.Entries, s.Entries)
		s.mu.Unlock()
		result = append(result, snapshot)
	}
	return result
}

func (t *Tracer) Record(traceID, module, stage, direction, appID, instanceID, summary string, detail map[string]interface{}, duration time.Duration) {
	if !t.enabled.Load() {
		return
	}

	entry := TraceEntry{
		ID:        t.entryIDSeq.Add(1),
		TraceID:   traceID,
		Timestamp: time.Now(),
		Module:    module,
		Stage:     stage,
		Direction: direction,
		AppID:     appID,
		Instance:  instanceID,
		Summary:   summary,
		Detail:    detail,
		Duration:  duration,
	}

	if traceID != "" {
		t.mu.RLock()
		if s, ok := t.sessions[traceID]; ok {
			s.mu.Lock()
			s.entrySeq++
			entry.Seq = s.entrySeq
			s.Entries = append(s.Entries, entry)
			s.mu.Unlock()
		}
		t.mu.RUnlock()
	}

	t.mu.Lock()
	if len(t.ringBuffer) < t.ringSize {
		t.ringBuffer = append(t.ringBuffer, entry)
	} else {
		t.ringBuffer[t.ringPos] = entry
	}
	t.ringPos = (t.ringPos + 1) % t.ringSize
	t.mu.Unlock()

	t.mu.RLock()
	for _, ch := range t.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
	t.mu.RUnlock()

	if t.stepMode.Load() && traceID != "" {
		t.mu.RLock()
		ch, hasPause := t.pauseCh[traceID]
		t.mu.RUnlock()
		if hasPause {
			<-ch
		}
	}
}

func (t *Tracer) Emit(module, stage, direction, appID, instanceID, summary string, detail map[string]interface{}) {
	t.Record("", module, stage, direction, appID, instanceID, summary, detail, 0)
}

func (t *Tracer) StepContinue(traceID string) {
	t.mu.RLock()
	ch, ok := t.pauseCh[traceID]
	t.mu.RUnlock()
	if ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (t *Tracer) Subscribe(id string) chan TraceEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := make(chan TraceEntry, 200)
	t.subscribers[id] = ch
	return ch
}

func (t *Tracer) Unsubscribe(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch, ok := t.subscribers[id]; ok {
		close(ch)
		delete(t.subscribers, id)
	}
}

func (t *Tracer) BufferLen() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ringBuffer)
}

func (t *Tracer) GetRecentEntries(limit int) []TraceEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := len(t.ringBuffer)
	if n == 0 {
		return []TraceEntry{}
	}
	if limit <= 0 || limit > n {
		limit = n
	}

	result := make([]TraceEntry, limit)
	start := (t.ringPos - limit + n) % n
	for i := 0; i < limit; i++ {
		result[i] = t.ringBuffer[(start+i)%n]
	}
	return result
}

func (t *Tracer) GetEntriesByApp(appID string, limit int) []TraceEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := len(t.ringBuffer)
	if n == 0 {
		return []TraceEntry{}
	}

	var result []TraceEntry
	for i := 0; i < n; i++ {
		idx := (t.ringPos + i) % n
		if t.ringBuffer[idx].AppID == appID {
			result = append(result, t.ringBuffer[idx])
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

func (t *Tracer) ClearAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ringBuffer = t.ringBuffer[:0]
	t.ringPos = 0
	for id := range t.sessions {
		delete(t.sessions, id)
	}
}

func TraceDetailFromJSON(data interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}

	switch v := data.(type) {
	case map[string]interface{}:
		return v
	case string:
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(v), &m); err == nil {
			return m
		}
		return map[string]interface{}{"raw": v}
	default:
		b, _ := json.Marshal(v)
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err == nil {
			return m
		}
		return map[string]interface{}{"raw": fmt.Sprintf("%v", v)}
	}
}
