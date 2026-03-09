package sandbox

import (
	"encoding/json"
	"log"
	"sync"
)

type PolicyEngine struct {
	store     *SandboxStore
	manifests map[string]*AppManifest
	eventBus  *EventBus
	mu        sync.RWMutex
}

func NewPolicyEngine(store *SandboxStore, eventBus *EventBus) *PolicyEngine {
	return &PolicyEngine{
		store:     store,
		manifests: make(map[string]*AppManifest),
		eventBus:  eventBus,
	}
}

func (pe *PolicyEngine) RegisterManifest(manifest *AppManifest) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.manifests[manifest.ID] = manifest
}

func (pe *PolicyEngine) UnregisterManifest(appID string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	delete(pe.manifests, appID)
}

func (pe *PolicyEngine) CheckDomain(instanceID, appID, domain, method, urlStr string) (action string, rule string) {
	pe.mu.RLock()
	manifest, hasManifest := pe.manifests[appID]
	pe.mu.RUnlock()

	userRules, err := pe.store.GetPolicyRules(appID)
	if err != nil {
		log.Printf("[policy] Failed to load user rules for app %s: %v", appID, err)
	}

	for _, r := range userRules {
		if r.RuleType == "domain_block" && MatchDomain(r.Target, domain) {
			pe.recordDecision(instanceID, appID, "proxy_request", "denied", domain, "user_block_rule: "+r.Target, "user")
			return "auto_blocked", "user_block:" + r.Target
		}
	}

	for _, r := range userRules {
		if r.RuleType == "domain_allow" && MatchDomain(r.Target, domain) {
			pe.recordDecision(instanceID, appID, "proxy_request", "approved", domain, "user_allow_rule: "+r.Target, "user")
			return "auto_approved", "user_allow:" + r.Target
		}
	}

	if hasManifest {
		allowed, explicit := manifest.IsDomainAllowed(domain)
		if explicit && !allowed {
			pe.recordDecision(instanceID, appID, "proxy_request", "denied", domain, "manifest_block: "+domain, "manifest_rule")
			return "auto_blocked", "manifest_block:" + domain
		}
		if explicit && allowed {
			pe.recordDecision(instanceID, appID, "proxy_request", "approved", domain, "manifest_allow: "+domain, "manifest_rule")
			return "auto_approved", "manifest_allow:" + domain
		}
	}

	pe.holdForOperator(instanceID, appID, domain, method, urlStr)
	return "held", "unknown_domain"
}

func (pe *PolicyEngine) CheckCapability(instanceID, appID, capability string) (allowed bool, rule string) {
	pe.mu.RLock()
	manifest, hasManifest := pe.manifests[appID]
	pe.mu.RUnlock()

	userRules, _ := pe.store.GetPolicyRules(appID)
	for _, r := range userRules {
		if r.RuleType == "capability_block" && r.Target == capability {
			pe.recordDecision(instanceID, appID, "resource_request", "denied", capability, "user_block_rule", "user")
			return false, "user_block"
		}
	}
	for _, r := range userRules {
		if r.RuleType == "capability_allow" && r.Target == capability {
			pe.recordDecision(instanceID, appID, "resource_request", "approved", capability, "user_allow_rule", "user")
			return true, "user_allow"
		}
	}

	if hasManifest {
		for _, c := range manifest.Capabilities.Blocked {
			if c == capability {
				pe.recordDecision(instanceID, appID, "resource_request", "denied", capability, "manifest_blocked", "manifest_rule")
				return false, "manifest_blocked"
			}
		}
		for _, c := range manifest.Capabilities.Allowed {
			if c == capability {
				pe.recordDecision(instanceID, appID, "resource_request", "approved", capability, "manifest_allowed", "manifest_rule")
				return true, "manifest_allowed"
			}
		}
	}

	return false, "not_declared"
}

func (pe *PolicyEngine) ProcessResourceRequest(instanceID, appID, resourceType, resourceTarget string) string {
	if resourceType == "network" {
		action, _ := pe.CheckDomain(instanceID, appID, resourceTarget, "", "")
		switch action {
		case "auto_approved":
			return "approved"
		case "auto_blocked":
			return "denied"
		default:
			return "pending"
		}
	}

	if resourceType == "device" {
		allowed, _ := pe.CheckCapability(instanceID, appID, resourceTarget)
		if allowed {
			return "approved"
		}
		return "denied"
	}

	return "pending"
}

func (pe *PolicyEngine) holdForOperator(instanceID, appID, domain, method, urlStr string) {
	pe.store.InsertProxyLog(ProxyLog{
		InstanceID:   instanceID,
		Direction:    "egress",
		Method:       strPtr(method),
		URL:          strPtr(urlStr),
		Domain:       strPtr(domain),
		PolicyAction: strPtr("held"),
		PolicyRule:   strPtr("unknown_domain"),
	})

	eventData, _ := json.Marshal(map[string]string{
		"domain":      domain,
		"method":      method,
		"url":         urlStr,
		"instance_id": instanceID,
	})
	pe.store.InsertEvent(Event{
		InstanceID: &instanceID,
		AppID:      &appID,
		EventType:  "proxy_request_held",
		EventData:  strPtr(string(eventData)),
	})

	if pe.eventBus != nil {
		pe.eventBus.Publish(SandboxEvent{
			Type:       "proxy_request_held",
			AppID:      appID,
			InstanceID: instanceID,
			Data: map[string]interface{}{
				"domain": domain,
				"method": method,
				"url":    urlStr,
			},
		})
	}

	log.Printf("[policy] Held request to %s for operator approval (app: %s, instance: %s)", domain, appID, instanceID)
}

func (pe *PolicyEngine) recordDecision(instanceID, appID, decisionType, action, target, reason, decidedBy string) {
	pe.store.InsertPolicyDecision(PolicyDecision{
		InstanceID:   &instanceID,
		AppID:        appID,
		DecisionType: decisionType,
		Action:       action,
		Target:       &target,
		Reason:       &reason,
		DecidedBy:    &decidedBy,
	})
}

func (pe *PolicyEngine) ApproveHeldRequest(logID int64, appID string) error {
	if err := pe.store.UpdateProxyLogAction(logID, "operator_approved", "operator"); err != nil {
		return err
	}

	pe.recordDecision("", appID, "proxy_request", "approved", "", "operator_approved", "user")

	if pe.eventBus != nil {
		pe.eventBus.Publish(SandboxEvent{
			Type:  "proxy_request_approved",
			AppID: appID,
			Data:  map[string]interface{}{"log_id": logID},
		})
	}

	return nil
}

func (pe *PolicyEngine) BlockHeldRequest(logID int64, appID string) error {
	if err := pe.store.UpdateProxyLogAction(logID, "operator_blocked", "operator"); err != nil {
		return err
	}

	pe.recordDecision("", appID, "proxy_request", "denied", "", "operator_blocked", "user")

	if pe.eventBus != nil {
		pe.eventBus.Publish(SandboxEvent{
			Type:  "proxy_request_blocked",
			AppID: appID,
			Data:  map[string]interface{}{"log_id": logID},
		})
	}

	return nil
}

func (pe *PolicyEngine) AddUserRule(appID, ruleType, target string) (int64, error) {
	return pe.store.SavePolicyRule(PolicyRule{
		AppID:    appID,
		RuleType: ruleType,
		Target:   target,
		Source:   "user",
	})
}

func (pe *PolicyEngine) RemoveUserRule(ruleID int64) error {
	return pe.store.DeletePolicyRule(ruleID)
}

func (pe *PolicyEngine) SyncManifestRules(manifest *AppManifest) error {
	for _, domain := range manifest.Network.AllowedDomains {
		pe.store.SavePolicyRule(PolicyRule{
			AppID:    manifest.ID,
			RuleType: "domain_allow",
			Target:   domain,
			Source:   "manifest",
		})
	}
	for _, domain := range manifest.Network.BlockedDomains {
		pe.store.SavePolicyRule(PolicyRule{
			AppID:    manifest.ID,
			RuleType: "domain_block",
			Target:   domain,
			Source:   "manifest",
		})
	}
	for _, cap := range manifest.Capabilities.Allowed {
		pe.store.SavePolicyRule(PolicyRule{
			AppID:    manifest.ID,
			RuleType: "capability_allow",
			Target:   cap,
			Source:   "manifest",
		})
	}
	for _, cap := range manifest.Capabilities.Blocked {
		pe.store.SavePolicyRule(PolicyRule{
			AppID:    manifest.ID,
			RuleType: "capability_block",
			Target:   cap,
			Source:   "manifest",
		})
	}
	return nil
}
