package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The template renderer substitutes on the decoded JSON tree: whole-string
// placeholders keep the arg's type, embedded ones stringify, defaults apply,
// and quotes/newlines in values can never break the document.
func TestRenderBodyTemplate(t *testing.T) {
	tmpl := json.RawMessage(`{"model":"{model|default-model}","n":"{count}","messages":[{"role":"user","content":"Subject: {prompt}"}]}`)

	out, err := renderBodyTemplate(tmpl, map[string]any{
		"prompt": "a \"quoted\"\nmultiline subject",
		"count":  float64(2),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v", err)
	}
	if got["model"] != "default-model" {
		t.Fatalf("default not applied: %v", got["model"])
	}
	if got["n"] != float64(2) {
		t.Fatalf("whole-string placeholder must keep the arg type, got %T %v", got["n"], got["n"])
	}
	msg := got["messages"].([]any)[0].(map[string]any)["content"].(string)
	if !strings.Contains(msg, "a \"quoted\"\nmultiline subject") {
		t.Fatalf("embedded substitution wrong: %q", msg)
	}

	if _, err := renderBodyTemplate(tmpl, map[string]any{"count": 1, "prompt": "x", "rogue": true}); err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("unreferenced args must error, got %v", err)
	}
	if _, err := renderBodyTemplate(tmpl, map[string]any{"count": 1}); err == nil || !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("missing required placeholder must error, got %v", err)
	}
}

// Response extraction projects to declared fields; "!" marks a path required.
func TestExtractResponseFields(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"images":[{"image_url":{"url":"data:image/png;base64,AAA"}}]}}],"model":"m1","usage":{"cost":0.07}}`)
	out, err := extractResponseFields(map[string]string{
		"image_data_url": "choices.0.message.images.0.image_url.url!",
		"model":          "model",
		"cost":           "usage.cost",
		"absent":         "no.such.path",
	}, body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["image_data_url"] != "data:image/png;base64,AAA" || got["model"] != "m1" || got["cost"] != 0.07 {
		t.Fatalf("bad projection: %v", got)
	}
	if _, present := got["absent"]; present {
		t.Fatal("optional missing path must be omitted")
	}
	if _, err := extractResponseFields(map[string]string{"x": "choices.9.nope!"}, body); err == nil {
		t.Fatal("required missing path must error")
	}
}

// End-to-end: a templated capability (the shape an image-generation record uses)
// renders its body from args, injects the vault credential at egress, and projects
// the response down to its declared contract.
func TestTemplatedCapabilityEndToEnd(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &gotBody)
		w.Write([]byte(`{"model":"default-image-model","choices":[{"message":{"images":[{"image_url":{"url":"data:image/png;base64,iVBOR"}}]}}],"usage":{"cost":0.068}}`))
	}))
	defer ts.Close()

	m := registryTestManager(t)
	rec := CapabilityRecord{
		ID: "imagesvc.image.create", Name: "Create an image", Domain: "media",
		ExecutorType: "external_api", Impact: "mutating",
		Egress: &EgressSpec{
			BaseURL: ts.URL, Method: "POST", PathTemplate: "/generate",
			CredentialService: "imagesvc",
			BodyTemplate:      json.RawMessage(`{"model":"{model|default-image-model}","modalities":["image","text"],"messages":[{"role":"user","content":[{"type":"text","text":"{prompt}"}]}]}`),
			ResponseExtract: map[string]string{
				"image_data_url": "choices.0.message.images.0.image_url.url!",
				"model":          "model",
				"cost":           "usage.cost",
			},
		},
		Provider: "registry-native", Enabled: true,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := m.credentials.SetCredential("imagesvc", []string{"127.0.0.1"}, map[string]string{"Authorization": "Bearer img-key"}); err != nil {
		t.Fatalf("credential: %v", err)
	}

	caller := CallerContext{Remote: false, CallerAID: "local-owner", CorrelationID: "corr-img", Transport: "mcp"}
	res, err := m.InvokeCapability(context.Background(), caller, "imagesvc.image.create", []byte(`{"prompt":"a lighthouse at dusk"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("status %d: %s", res.Status, res.Body)
	}
	if gotAuth != "Bearer img-key" {
		t.Fatalf("credential not injected at egress, got %q", gotAuth)
	}
	if gotBody["model"] != "default-image-model" {
		t.Fatalf("default model not applied: %v", gotBody["model"])
	}
	mods, _ := json.Marshal(gotBody["modalities"])
	if string(mods) != `["image","text"]` {
		t.Fatalf("modalities wrong: %s", mods)
	}
	text := gotBody["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]
	if text != "a lighthouse at dusk" {
		t.Fatalf("prompt not threaded: %v", text)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("projected body not JSON: %v", err)
	}
	if out["image_data_url"] != "data:image/png;base64,iVBOR" || out["cost"] != 0.068 {
		t.Fatalf("bad projection: %v", out)
	}

	// A response missing the required field must fail loudly.
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"no image"}}]}`))
	}))
	defer ts2.Close()
	rec.Egress.BaseURL = ts2.URL
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InvokeCapability(context.Background(), caller, "imagesvc.image.create", []byte(`{"prompt":"x"}`)); err == nil {
		t.Fatal("missing required response field must be an error")
	}
}
