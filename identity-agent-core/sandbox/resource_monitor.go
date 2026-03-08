package sandbox

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type EscalationLevel int

const (
	EscalationNone    EscalationLevel = 0
	EscalationWarning EscalationLevel = 1
	EscalationAsk     EscalationLevel = 2
	EscalationKill    EscalationLevel = 3
)

type ResourceAlert struct {
	InstanceID string          `json:"instance_id"`
	AppID      string          `json:"app_id"`
	Level      EscalationLevel `json:"level"`
	Resource   string          `json:"resource"`
	Current    int64           `json:"current"`
	Limit      int64           `json:"limit"`
	Percent    float64         `json:"percent"`
	Message    string          `json:"message"`
	Timestamp  string          `json:"timestamp"`
}

type ResourceAlertCallback func(alert ResourceAlert)

type ResourceMonitor struct {
	runtime     Runtime
	manifest    *AppManifest
	instance    *Instance
	store       *SandboxStore
	interval    time.Duration
	killTimeout time.Duration
	callback    ResourceAlertCallback
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	escalations map[string]EscalationLevel
	askTimers   map[string]time.Time
}

func NewResourceMonitor(
	rt Runtime,
	manifest *AppManifest,
	instance *Instance,
	store *SandboxStore,
	callback ResourceAlertCallback,
) *ResourceMonitor {
	return &ResourceMonitor{
		runtime:     rt,
		manifest:    manifest,
		instance:    instance,
		store:       store,
		interval:    10 * time.Second,
		killTimeout: 60 * time.Second,
		callback:    callback,
		escalations: make(map[string]EscalationLevel),
		askTimers:   make(map[string]time.Time),
	}
}

func (m *ResourceMonitor) Start(ctx context.Context) {
	monitorCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.run(monitorCtx)
	}()

	log.Printf("[resource-monitor] Started monitoring instance %s (app: %s)", m.instance.ID, m.manifest.ID)
}

func (m *ResourceMonitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	log.Printf("[resource-monitor] Stopped monitoring instance %s", m.instance.ID)
}

func (m *ResourceMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

func (m *ResourceMonitor) check(ctx context.Context) {
	stats, err := m.runtime.Stats(ctx)
	if err != nil {
		return
	}

	if stats.MemoryLimitMB > 0 {
		m.checkResource(ctx, "memory", stats.MemoryUsedMB, stats.MemoryLimitMB)
	}

	if stats.DiskLimitMB > 0 {
		m.checkResource(ctx, "disk", stats.DiskUsedMB, stats.DiskLimitMB)
	}

	if m.manifest.Resources.CPUCores > 0 {
		cpuLimit := int64(m.manifest.Resources.CPUCores * 100)
		m.checkResource(ctx, "cpu", int64(stats.CPUPercent), cpuLimit)
	}
}

func (m *ResourceMonitor) checkResource(ctx context.Context, resource string, current, limit int64) {
	if limit <= 0 {
		return
	}

	percent := float64(current) / float64(limit) * 100

	m.mu.Lock()
	currentLevel := m.escalations[resource]
	m.mu.Unlock()

	if percent >= 100 {
		m.escalate(ctx, resource, current, limit, percent, EscalationAsk)
	} else if percent >= 80 {
		if currentLevel < EscalationWarning {
			m.escalate(ctx, resource, current, limit, percent, EscalationWarning)
		}
	} else {
		m.mu.Lock()
		if currentLevel > EscalationNone {
			m.escalations[resource] = EscalationNone
			delete(m.askTimers, resource)
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	if askTime, exists := m.askTimers[resource]; exists {
		if time.Since(askTime) > m.killTimeout {
			m.mu.Unlock()
			m.escalate(ctx, resource, current, limit, percent, EscalationKill)
			return
		}
	}
	m.mu.Unlock()
}

func (m *ResourceMonitor) escalate(ctx context.Context, resource string, current, limit int64, percent float64, level EscalationLevel) {
	m.mu.Lock()
	currentLevel := m.escalations[resource]
	if level <= currentLevel && level != EscalationKill {
		m.mu.Unlock()
		return
	}
	m.escalations[resource] = level
	if level == EscalationAsk {
		if _, exists := m.askTimers[resource]; !exists {
			m.askTimers[resource] = time.Now()
		}
	}
	m.mu.Unlock()

	alert := ResourceAlert{
		InstanceID: m.instance.ID,
		AppID:      m.manifest.ID,
		Level:      level,
		Resource:   resource,
		Current:    current,
		Limit:      limit,
		Percent:    percent,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	switch level {
	case EscalationWarning:
		alert.Message = fmt.Sprintf("App %s approaching %s limit: %.0f%% used (%d/%d MB)",
			m.manifest.Name, resource, percent, current, limit)
		log.Printf("[resource-monitor] WARNING: %s", alert.Message)

		m.logDecision("resource_limit_warning", "warned", resource, alert.Message)
		m.logEvent("resource_limit_warning", alert)

	case EscalationAsk:
		alert.Message = fmt.Sprintf("App %s exceeded %s limit: %.0f%% used (%d/%d MB). Allocate more resources? (auto-kill in %s)",
			m.manifest.Name, resource, percent, current, limit, m.killTimeout)
		log.Printf("[resource-monitor] ASK: %s", alert.Message)

		m.logDecision("resource_limit_exceeded", "asked", resource, alert.Message)
		m.logEvent("resource_limit_warning", alert)

	case EscalationKill:
		alert.Message = fmt.Sprintf("App %s killed: %s limit exceeded (%.0f%%, %d/%d MB) with no user response within %s",
			m.manifest.Name, resource, percent, current, limit, m.killTimeout)
		log.Printf("[resource-monitor] KILL: %s", alert.Message)

		m.logDecision("resource_limit_killed", "killed", resource, alert.Message)
		m.logEvent("resource_limit_killed", alert)

		go func() {
			killCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := m.runtime.Stop(killCtx); err != nil {
				log.Printf("[resource-monitor] Failed to kill instance %s: %v", m.instance.ID, err)
			}
		}()
	}

	if m.callback != nil {
		m.callback(alert)
	}
}

func (m *ResourceMonitor) ApproveMoreResources(resource string, newLimit int64) {
	m.mu.Lock()
	m.escalations[resource] = EscalationNone
	delete(m.askTimers, resource)
	m.mu.Unlock()

	m.logDecision("limit_escalation", "approved", resource,
		fmt.Sprintf("User approved increased %s limit to %d", resource, newLimit))

	log.Printf("[resource-monitor] User approved increased %s limit to %d for instance %s",
		resource, newLimit, m.instance.ID)
}

func (m *ResourceMonitor) DenyMoreResources(resource string) {
	m.mu.Lock()
	delete(m.askTimers, resource)
	m.mu.Unlock()

	m.logDecision("limit_escalation", "denied", resource,
		fmt.Sprintf("User denied increased %s resources", resource))

	go func() {
		killCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.runtime.Stop(killCtx); err != nil {
			log.Printf("[resource-monitor] Failed to kill instance %s after deny: %v", m.instance.ID, err)
		}
	}()
}

func (m *ResourceMonitor) logDecision(decisionType, action, target, reason string) {
	m.store.InsertPolicyDecision(PolicyDecision{
		InstanceID:   &m.instance.ID,
		AppID:        m.manifest.ID,
		DecisionType: decisionType,
		Action:       action,
		Target:       &target,
		Reason:       &reason,
		DecidedBy:    strPtr("system"),
	})
}

func (m *ResourceMonitor) logEvent(eventType string, alert ResourceAlert) {
	dataBytes, _ := marshalJSON(alert)
	appID := m.manifest.ID
	m.store.InsertEvent(Event{
		InstanceID: &m.instance.ID,
		AppID:      &appID,
		EventType:  eventType,
		EventData:  strPtr(string(dataBytes)),
	})
}

func marshalJSON(v interface{}) ([]byte, error) {
	import "encoding/json"
	return json.Marshal(v)
}
