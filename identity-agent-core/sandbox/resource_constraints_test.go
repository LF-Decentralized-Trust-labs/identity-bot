package sandbox

import "testing"

func TestEnforceResourceConstraints(t *testing.T) {
	constraints := map[string]interface{}{
		"infra.dns_record.create": map[string]interface{}{
			"zone_id": []interface{}{"zoneA", "zoneB"},
		},
	}
	// Unconstrained capability → allowed.
	if err := enforceResourceConstraints(constraints, "infra.zone.list", []byte(`{}`)); err != nil {
		t.Fatalf("unconstrained capability should pass, got %v", err)
	}
	// Allowed value → allowed.
	if err := enforceResourceConstraints(constraints, "infra.dns_record.create", []byte(`{"zone_id":"zoneA","name":"x"}`)); err != nil {
		t.Fatalf("allowed zone should pass, got %v", err)
	}
	// Disallowed value → denied.
	if err := enforceResourceConstraints(constraints, "infra.dns_record.create", []byte(`{"zone_id":"zoneZ"}`)); err == nil {
		t.Fatal("a zone outside the allowlist must be denied")
	}
	// Missing constrained arg → denied.
	if err := enforceResourceConstraints(constraints, "infra.dns_record.create", []byte(`{"name":"x"}`)); err == nil {
		t.Fatal("a missing constrained argument must be denied")
	}
	// No constraints at all → allowed.
	if err := enforceResourceConstraints(nil, "infra.dns_record.create", []byte(`{"zone_id":"zoneZ"}`)); err != nil {
		t.Fatalf("nil constraints should pass, got %v", err)
	}
}
