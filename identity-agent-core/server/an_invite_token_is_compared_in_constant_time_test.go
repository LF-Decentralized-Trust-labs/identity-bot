package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// An invite token is the secret an invited owner's QR code carries. Compared
// with == or !=, the comparison stops at the first byte that differs, and the
// time it takes tells someone guessing how much of a guess was right. The
// property is timing, which a test cannot measure reliably, so this reads the
// code instead: nothing in the ownership ceremony compares a token with == or
// !=, apart from asking whether it is empty.
func TestTheCeremonyComparesNoTokenWithAnOrdinaryComparison(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range []string{"owner_ceremony.go", "owner_ceremony_handlers.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			b, ok := n.(*ast.BinaryExpr)
			if !ok || (b.Op != token.EQL && b.Op != token.NEQ) {
				return true
			}
			if isEmptyString(b.X) || isEmptyString(b.Y) {
				return true
			}
			if namesAToken(b.X) || namesAToken(b.Y) {
				t.Errorf("%s compares a token with %s", fset.Position(b.Pos()), b.Op)
			}
			return true
		})
	}
}

func namesAToken(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return strings.EqualFold(v.Name, "token")
	case *ast.SelectorExpr:
		return v.Sel.Name == "Token" || v.Sel.Name == "InviteToken"
	}
	return false
}

func isEmptyString(e ast.Expr) bool {
	l, ok := e.(*ast.BasicLit)
	return ok && l.Kind == token.STRING && (l.Value == `""` || l.Value == "``")
}

// A redemption with no token belongs to no ceremony, even if an invite was
// somehow recorded without one.
func TestAnEmptyTokenRedeemsNoCeremonyInvite(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	c := &OwnerCeremony{Status: ceremonyCollecting, Invited: []CeremonyInvitee{{Token: ""}}}
	if err := s.saveCeremony(c); err != nil {
		t.Fatal(err)
	}
	got, complete, err := s.recordAcceptance("", "EOwner", "key", "next")
	if err != nil || got != nil || complete {
		t.Fatalf("an empty token redeemed an invite: %v %v %v", got, complete, err)
	}
}
