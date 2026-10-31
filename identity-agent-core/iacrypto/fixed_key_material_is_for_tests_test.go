package iacrypto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Fixed key material has private halves anyone can rebuild from its seed, so
// an identity founded on it would belong to everyone. Only tests and vector
// generation may reach it. A production path that called it once let a
// request found an identity, or mint a break-glass root, from it.
//
// Every Go file of the module other than a test is parsed and every reference
// to the function is found in its syntax tree, so a call split across lines,
// a function value passed or stored, or a renamed import is caught as surely
// as a plain call.
func TestFixedKeyMaterialIsReachedOnlyFromTests(t *testing.T) {
	const name = "SyntheticHybridKeyMaterial"
	root := ".."
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			n := d.Name()
			if path != root && (n == "vendor" || n == "testdata" || n == "node_modules" || strings.HasPrefix(n, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		// The names this file imports the iacrypto package under.
		aliases := map[string]bool{}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) != "identity-agent-core/iacrypto" {
				continue
			}
			if imp.Name != nil {
				aliases[imp.Name.Name] = true
			} else {
				aliases["iacrypto"] = true
			}
		}
		// A bare name refers to it inside the package, or through a dot import.
		bare := f.Name.Name == "iacrypto" || aliases["."]
		var decl *ast.Ident
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name && f.Name.Name == "iacrypto" {
				decl = fn.Name
			}
		}
		var visit func(ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && aliases[x.Name] && n.Sel.Name == name {
					t.Errorf("%s reaches fixed key material outside a test", fset.Position(n.Pos()))
				}
				// What is selected from is walked; the selected name is a
				// field or method of something else, not the function.
				ast.Inspect(n.X, visit)
				return false
			case *ast.Ident:
				if bare && n != decl && n.Name == name {
					t.Errorf("%s reaches fixed key material outside a test", fset.Position(n.Pos()))
				}
			}
			return true
		}
		ast.Inspect(f, visit)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
