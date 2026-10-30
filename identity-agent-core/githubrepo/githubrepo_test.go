package githubrepo

import "testing"

func TestARepositoryIsNamedAsOwnerAndName(t *testing.T) {
	for in, want := range map[string]string{
		"Acme/Sandbox": "acme/sandbox", "https://github.com/acme/site.git": "acme/site", " acme/a.b-c_d ": "acme/a.b-c_d",
		"acme/.github": "acme/.github", "acme/_site": "acme/_site", "acme/-x": "acme/-x", "acme/...x": "acme/...x",
	} {
		if got, err := NormaliseRepository(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"acme", "acme/", "/x", "acme/x/y", "acme/..", "acme/.", "ac me/x", "acme/x?y", "-acme/x", ".acme/x"} {
		if _, err := NormaliseRepository(bad); err == nil {
			t.Errorf("%q was taken as a repository", bad)
		}
	}
}
