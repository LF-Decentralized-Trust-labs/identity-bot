package addon_test

import (
	"net/http"
	"reflect"
	"testing"

	"identity-agent-core/addon"
	"identity-agent-core/didcomm"
)

// An add-on's routes are its own, opened or closed by its own entries in the
// route tables. Were the handle to give it a core handler, or the router that
// serves them, it could serve that handler from a route of its own and make
// public what the core keeps for the owner. So nothing on the handle is a
// handler (it answers a request and returns nothing), and nothing returns
// one or a router.
func TestTheHandleGivesNoCoreHandler(t *testing.T) {
	handler := reflect.TypeOf((*http.Handler)(nil)).Elem()
	w := reflect.TypeOf((*http.ResponseWriter)(nil)).Elem()
	r := reflect.TypeOf((*http.Request)(nil))
	for _, iface := range []reflect.Type{
		reflect.TypeOf((*addon.Host)(nil)).Elem(),
		reflect.TypeOf((*addon.Helpers)(nil)).Elem(),
	} {
		for i := 0; i < iface.NumMethod(); i++ {
			m := iface.Method(i)
			ft := m.Type
			if ft.NumIn() == 2 && ft.In(0) == w && ft.In(1) == r && ft.NumOut() == 0 {
				t.Errorf("%s.%s is a handler", iface.Name(), m.Name)
			}
			for o := 0; o < ft.NumOut(); o++ {
				out := ft.Out(o)
				if out.Implements(handler) || (out.Kind() == reflect.Func && out.NumIn() == 2 && out.In(0) == w && out.In(1) == r) {
					t.Errorf("%s.%s returns a handler or a router (%s)", iface.Name(), m.Name, out)
				}
			}
		}
	}
}

// Nor does the handle give out a key: the core signs, seals and opens with
// the keys it holds, and an add-on asks it to. No method returns a DIDComm
// keyset, whose private keys are in it.
func TestTheHandleGivesNoKeySet(t *testing.T) {
	keySet := reflect.TypeOf((*didcomm.KeySet)(nil))
	for _, iface := range []reflect.Type{
		reflect.TypeOf((*addon.Host)(nil)).Elem(),
		reflect.TypeOf((*addon.Helpers)(nil)).Elem(),
	} {
		for i := 0; i < iface.NumMethod(); i++ {
			m := iface.Method(i)
			for o := 0; o < m.Type.NumOut(); o++ {
				if m.Type.Out(o) == keySet || m.Type.Out(o) == keySet.Elem() {
					t.Errorf("%s.%s gives out a DIDComm keyset", iface.Name(), m.Name)
				}
			}
		}
	}
}
