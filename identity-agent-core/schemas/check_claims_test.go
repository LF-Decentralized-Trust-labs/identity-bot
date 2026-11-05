package schemas

import (
	"strings"
	"testing"
)

func TestCheckClaimsHoldsClaimsToTheSchema(t *testing.T) {
	good := map[string]interface{}{
		"org_name": "Acme", "org_aid": "Eabc", "employee_name": "A B", "role": "Dev",
		"permissions": []interface{}{"sign_contracts"}, "expiry_date": "2027-01-31",
	}
	if err := EmployeeAuthorization.CheckClaims(good); err != nil {
		t.Fatalf("conforming claims refused: %v", err)
	}
	clone := func(k string, v interface{}) map[string]interface{} {
		m := map[string]interface{}{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, c := range []struct {
		name   string
		claims map[string]interface{}
		field  string
	}{
		{"required field missing", clone("role", nil), `"role"`},
		{"undeclared field", clone("salary", "1"), `"salary"`},
		{"wrong type", clone("org_name", 7), `"org_name"`},
		{"list of non-strings", clone("permissions", []interface{}{1}), `"permissions"`},
		{"not a date", clone("expiry_date", "next week"), `"expiry_date"`},
	} {
		err := EmployeeAuthorization.CheckClaims(c.claims)
		if err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: got %v, want a refusal naming %s", c.name, err, c.field)
		}
	}
	// Allowed values, ranges, integers.
	if err := Guardianship.CheckClaims(map[string]interface{}{"dependent_name": "x", "guardian_type": "parent"}); err == nil || !strings.Contains(err.Error(), `"guardian_type"`) {
		t.Errorf("a guardian_type outside the schema's values: %v", err)
	}
	if err := Guardianship.CheckClaims(map[string]interface{}{"dependent_name": "x", "guardian_type": "elderly"}); err != nil {
		t.Errorf("a guardian_type inside the schema's values: %v", err)
	}
	if err := IdentityAttestation.CheckClaims(map[string]interface{}{"subject_name": "x", "assurance_level": "ial2", "confidence_score": float64(101)}); err == nil || !strings.Contains(err.Error(), `"confidence_score"`) {
		t.Errorf("a score above the maximum: %v", err)
	}
	if err := ProofOfAge.CheckClaims(map[string]interface{}{"over_21": true, "minimum_age": 21.5}); err == nil {
		t.Error("a fractional integer was accepted")
	}
}
