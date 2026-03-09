package sandbox

import (
	"sync"
)

type SandboxEvent struct {
	Type       string                 `json:"type"`
	AppID      string                 `json:"app_id"`
	InstanceID string                 `json:"instance_id,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

type EventBus struct {
	subscribers map[string]chan SandboxEvent
	mu          sync.RWMutex
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string]chan SandboxEvent),
	}
}

func (eb *EventBus) Subscribe(id string) chan SandboxEvent {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan SandboxEvent, 100)
	eb.subscribers[id] = ch
	return ch
}

func (eb *EventBus) Unsubscribe(id string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if ch, ok := eb.subscribers[id]; ok {
		close(ch)
		delete(eb.subscribers, id)
	}
}

func (eb *EventBus) Publish(event SandboxEvent) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}
