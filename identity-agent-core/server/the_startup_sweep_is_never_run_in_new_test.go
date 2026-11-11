package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The sweep of old finalizations reads key logs, so New must start it in the
// background (StartSettlingUnfinalized) and never run it (SettleUnfinalized)
// itself, which would hold up starting for as long as the logs take to read.
func TestNewStartsTheSweepInTheBackgroundOnly(t *testing.T) {
	fset := token.NewFileSet()
	files, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	for _, pkg := range files {
		for name, f := range pkg.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "New" || fn.Recv != nil || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
							switch sel.Sel.Name {
							case "SettleUnfinalized":
								t.Errorf("%s: New runs SettleUnfinalized in the start path", name)
							case "StartSettlingUnfinalized":
								started = true
							}
						}
					}
					return true
				})
			}
		}
	}
	if !started {
		t.Fatal("New does not start the sweep of old finalizations")
	}
}
