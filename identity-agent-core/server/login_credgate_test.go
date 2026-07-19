package server

import "testing"

func credACDC(schema, issuer, status string) map[string]interface{} {
	return map[string]interface{}{"schema_said": schema, "issuer_aid": issuer, "status": status}
}

func TestPresentsRequiredCredential(t *testing.T) {
	emp := []interface{}{credACDC("SCHEMA_EMP", "AID_ORG", "issued")}
	cases := []struct {
		name           string
		presented      []interface{}
		schema, issuer string
		want           bool
	}{
		{"match schema+issuer", emp, "SCHEMA_EMP", "AID_ORG", true},
		{"match schema, any issuer", emp, "SCHEMA_EMP", "", true},
		{"wrong schema", emp, "SCHEMA_OTHER", "", false},
		{"wrong issuer", emp, "SCHEMA_EMP", "AID_OTHER", false},
		{"revoked not accepted", []interface{}{credACDC("SCHEMA_EMP", "AID_ORG", "revoked")}, "SCHEMA_EMP", "AID_ORG", false},
		{"none presented", []interface{}{}, "SCHEMA_EMP", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := presentsRequiredCredential(c.presented, c.schema, c.issuer); got != c.want {
				t.Fatalf("presentsRequiredCredential(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
