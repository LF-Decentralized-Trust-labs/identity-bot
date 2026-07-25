package sandbox

import "testing"

// A host plug-in's launched binary must NOT receive proxy env (it isn't routed
// through the MITM proxy); a sandboxed binary must.
func TestBinaryRuntimeProxyEnvByIsolation(t *testing.T) {
	inst := &Instance{ID: "i1", AppID: "p1"}

	host := &AppManifest{ID: "p1", Isolation: "host", Binary: &BinaryConfig{Path: "/bin/true"}}
	rt, err := NewBinaryRuntime(host, inst, nil, "http://127.0.0.1:9", 9)
	if err != nil {
		t.Fatal(err)
	}
	env := rt.NetworkConfig().EnvVars
	if _, ok := env["HTTP_PROXY"]; ok {
		t.Fatal("host plug-in must not get HTTP_PROXY")
	}
	if env["DISPLAY_PORT"] == "" || env["IDENTITY_AGENT_API"] == "" {
		t.Fatal("host plug-in still needs DISPLAY_PORT + IDENTITY_AGENT_API")
	}

	sandboxed := &AppManifest{ID: "p2", Binary: &BinaryConfig{Path: "/bin/true"}}
	rt2, err := NewBinaryRuntime(sandboxed, inst, nil, "http://127.0.0.1:9", 9)
	if err != nil {
		t.Fatal(err)
	}
	if rt2.NetworkConfig().EnvVars["HTTP_PROXY"] == "" {
		t.Fatal("sandboxed plug-in must get HTTP_PROXY")
	}
}
