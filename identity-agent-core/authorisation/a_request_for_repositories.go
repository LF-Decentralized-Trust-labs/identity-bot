package authorisation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"identity-agent-core/githubapp"
)

// A request can change only which GitHub repositories an AI agent may use:
// PUT /api/mcp/agents/{id}/github, whose body names each repository and
// whether the AI agent may read it or also write to it. The grant issued on it
// is checked against that.
//
// What it vouches for is the repositories. The grant gives exactly the
// repositories asked for, at the access asked for: write where write was
// asked, and every one asked for under read, since write includes read. A
// grant that gives a repository nobody asked for, or leaves one out, does not
// rest on the request.
//
// What it does not vouch for is the rest of the grant. The request asked
// nothing about the AI agent's other capabilities, which the grant carries from
// the one it replaces, and which rest on whatever request issued that one. Nor
// does it vouch for GitHub's number for each repository: the Identity Agent
// asks GitHub for it, and the request names repositories only by owner/name.

// checkRepositoriesAsked checks the repositories a grant gives against those a
// request asked for.
func checkRepositoriesAsked(cred acdc, raw json.RawMessage) error {
	var asked []struct {
		Repository string `json:"repository"`
		Access     string `json:"access"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &asked) != nil || asked == nil {
		return fmt.Errorf("the request names no list of repositories")
	}
	want := map[string]githubapp.Access{}
	for _, x := range asked {
		name, err := githubapp.NormaliseRepository(x.Repository)
		if err != nil {
			return fmt.Errorf("the request names a repository that is not one: %w", err)
		}
		access, err := githubapp.ParseAccess(x.Access)
		if err != nil {
			return fmt.Errorf("the request names an access that is not one: %w", err)
		}
		if access == githubapp.Write || want[name] == "" {
			want[name] = access
		}
	}
	var caps []string
	if err := json.Unmarshal(cred.A["capabilities"], &caps); err != nil {
		return fmt.Errorf("the grant's capabilities are unreadable")
	}
	limits := map[string]map[string][]string{}
	if rc, ok := cred.A["resource_constraints"]; ok {
		if err := json.Unmarshal(rc, &limits); err != nil {
			return fmt.Errorf("the grant's limits are unreadable")
		}
	}
	for _, access := range []githubapp.Access{githubapp.Read, githubapp.Write} {
		capID := access.Capability()
		var expected []string
		for name, a := range want {
			if access == githubapp.Read || a == githubapp.Write {
				expected = append(expected, name)
			}
		}
		sort.Strings(expected)
		granted := false
		for _, c := range caps {
			granted = granted || c == capID
		}
		limit, limited := limits[capID]
		if len(expected) == 0 {
			if granted || limited {
				return fmt.Errorf("the grant gives %s on repositories the request did not ask for", capID)
			}
			continue
		}
		if !granted || !limited {
			return fmt.Errorf("the grant does not give %s on the repositories the request asked for", capID)
		}
		var got []string
		for _, n := range limit[githubapp.RepositoryArgument] {
			name, err := githubapp.NormaliseRepository(n)
			if err != nil {
				return fmt.Errorf("the grant names a repository that is not one: %w", err)
			}
			got = append(got, name)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, expected) {
			return fmt.Errorf("the grant gives %s on other repositories than the request asked for", capID)
		}
		// Each repository is also named by GitHub's number for it, in the same
		// place: a grant naming it without its number gives nothing, so one
		// whose lists differ in length does not give what was asked.
		if len(limit[githubapp.RepositoryIDArgument]) != len(got) {
			return fmt.Errorf("the grant does not name each repository the request asked for by GitHub's number")
		}
	}
	return nil
}
