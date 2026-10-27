package brainsignin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/brainsignin"
)

// A model server is never checked on the Identity Agent's own computer, at a
// link-local or cloud metadata address, or at another reserved one; one on a
// private network or the internet is.
func TestAModelServerIsNotCheckedAtAReservedAddress(t *testing.T) {
	for addr, refused := range map[string]bool{
		"127.0.0.1": true, "::1": true, "0.0.0.0": true, "::": true, "169.254.169.254": true, "fe80::1": true,
		"100.100.100.200": true, "168.63.129.16": true, "fd00:ec2::254": true, "224.0.0.1": true,
		"255.255.255.255": true, "::ffff:127.0.0.1": true, "64:ff9b::7f00:1": true, "::ffff:169.254.169.254": true,
		"10.0.0.5": false, "192.168.1.20": false, "172.16.4.4": false, "fd12:3456::1": false, "203.0.113.7": false,
		"8.8.8.8": false,
	} {
		err := brainsignin.ModelServerAddress(netip.MustParseAddr(addr))
		if (err != nil) != refused {
			t.Errorf("%s: %v, want refused=%v", addr, err, refused)
		}
	}
}

// modelServer is a model server on this computer, reached by a name only the
// checker's resolver knows, which writes down what it was asked.
type modelServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func newModelServer(t *testing.T, status int) *modelServer {
	m := &modelServer{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.seen = append(m.seen, r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
		m.mu.Unlock()
		rw.WriteHeader(status)
		_, _ = rw.Write([]byte(`{"data":[],"error":"the server's own words"}`))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *modelServer) port() string {
	u, _ := url.Parse(m.srv.URL)
	return u.Port()
}

func (m *modelServer) asked() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.seen...)
}

// checker resolves names with resolve, and allows this computer only, so a
// test server can stand in for one on the network.
func checker(resolve func(ctx context.Context, host string) ([]netip.Addr, error)) brainsignin.Checker {
	return brainsignin.Checker{
		Send: func(ctx context.Context, req *http.Request, client *http.Client) (*http.Response, error) {
			return client.Do(req)
		},
		Resolve: resolve,
		AddressRule: func(a netip.Addr) error {
			if a.IsLoopback() {
				return nil
			}
			return brainsignin.ModelServerAddress(a)
		},
	}
}

func local(endpoint string) brainsignin.Record {
	return brainsignin.Record{Kind: brainsignin.KindLocal, Provider: brainsignin.OpenAICompatible, Endpoint: endpoint,
		Secret: "MODEL-KEY"}
}

// A model server is asked one fixed question at its scheme and host: whatever
// path, query or user name its address carries is not used, and an address
// that carries a user name or password is refused before anything is sent.
func TestAModelServerIsAskedOnlyTheFixedQuestion(t *testing.T) {
	m := newModelServer(t, http.StatusOK)
	c := checker(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	res := c.Check(context.Background(), local("http://model.test:"+m.port()+"/admin/delete?all=1#x"))
	if !res.OK {
		t.Fatalf("not checked: %+v", res)
	}
	if got := m.asked(); len(got) != 1 || got[0] != "/v1/models Bearer MODEL-KEY" {
		t.Fatalf("the server was asked %v", got)
	}
	res = c.Check(context.Background(), local("http://someone:secret@model.test:"+m.port()))
	if res.OK || !strings.Contains(res.Why, "user name or password") || len(m.asked()) != 1 {
		t.Fatalf("an address with a user name and password: %+v, asked %v", res, m.asked())
	}
}

// A name any of whose addresses is reserved is not checked at all, and a
// name is resolved once: the request goes to the address that was checked,
// so a name that answers differently a moment later reaches nowhere else.
// Before, the address was given to an ordinary client, which looked the name
// up again when it connected.
func TestAModelServerIsReachedOnlyAtTheAddressChecked(t *testing.T) {
	m := newModelServer(t, http.StatusOK)
	calls := 0
	rebinding := checker(func(context.Context, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})
	if res := rebinding.Check(context.Background(), local("http://model.test:"+m.port())); !res.OK || calls != 1 ||
		len(m.asked()) != 1 {
		t.Fatalf("checked %+v, resolved %d times, asked %v", res, calls, m.asked())
	}
	mixed := checker(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}, nil
	})
	if res := mixed.Check(context.Background(), local("http://model.test:"+m.port())); res.OK ||
		!strings.Contains(res.Why, "reserved address") || len(m.asked()) != 1 {
		t.Fatalf("a name with a metadata address among its addresses: %+v, asked %v", res, m.asked())
	}
	// The real rule refuses this computer, by address and by name.
	strict := brainsignin.Checker{Send: rebinding.Send}
	for _, e := range []string{m.srv.URL, "http://localhost:" + m.port(), "http://[::1]:" + m.port()} {
		if res := strict.Check(context.Background(), local(e)); res.OK || len(m.asked()) != 1 {
			t.Fatalf("%s: %+v, asked %v", e, res, m.asked())
		}
	}
}

// What a model server answered is never passed back: not its status, not its
// words.
func TestACheckSaysNothingTheServerAnswered(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusUnauthorized,
		http.StatusFound} {
		m := newModelServer(t, status)
		c := checker(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		})
		res := c.Check(context.Background(), local("http://model.test:"+m.port()))
		if res.OK || strings.ContainsAny(res.Why, "0123456789") || strings.Contains(res.Why, "own words") || res.Why == "" {
			t.Errorf("%d: %+v", status, res)
		}
	}
}
