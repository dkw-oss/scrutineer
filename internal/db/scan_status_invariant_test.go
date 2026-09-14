package db

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests hold the invariant scan_status.go documents: the derived scan
// state columns are only written through the helpers there, so status,
// status_priority and finished_at cannot drift apart. They parse every
// non-test .go file in the repository — the same technique as
// internal/web/openapi_routes_test.go — because nothing in the schema or the
// type system can enforce this.
//
// Test files are exempt: fixtures legitimately build rows in shapes
// production never produces, and forcing them through the helpers would hide
// what a test is setting up.

// governedScanFields are the derived Scan columns only scan_status.go may
// write, keyed by Go field name and by database column name.
var (
	governedScanFields  = map[string]bool{"StatusPriority": true, "FinishedAt": true}
	governedScanColumns = map[string]bool{"status_priority": true, "finished_at": true}
)

func TestScanStateIsOnlyWrittenThroughTheHelpers(t *testing.T) {
	var violations []string
	forEachRepoGoFile(t, func(path string, fset *token.FileSet, file *ast.File) {
		if path == "internal/db/scan_status.go" {
			return // the helpers themselves own these fields
		}
		ast.Inspect(file, func(n ast.Node) bool {
			violations = append(violations, governedFieldAssignments(fset, n)...)
			violations = append(violations, governedScanLiteralKeys(fset, n)...)
			violations = append(violations, governedUpdatesMapKeys(fset, n)...)
			return true
		})
	})
	if len(violations) > 0 {
		t.Errorf("scan state written by hand; route these through db.StampScanStatus / db.SetScanStatus / "+
			"db.ScanStatusUpdates / db.RequeueScanUpdates so status, status_priority and finished_at move together:\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestTerminalScanStatusWritesStampTheRow flags a function that moves a scan
// into a terminal state without stamping the derived columns. Writing only
// the status is how a finished row keeps sorting as running, or drops out of
// every timeline for want of a finished_at.
func TestTerminalScanStatusWritesStampTheRow(t *testing.T) {
	// finishErroredScan picks the status for finishScan, its only caller,
	// which stamps the row once after every branch has spoken; see the
	// comment there.
	allowed := map[string]bool{"internal/worker/worker.go:finishErroredScan": true}
	var violations []string
	forEachRepoGoFile(t, func(path string, fset *token.FileSet, file *ast.File) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			writes := terminalStatusWrites(fn.Body)
			if len(writes) == 0 || callsScanStampHelper(fn.Body) || allowed[path+":"+fn.Name.Name] {
				continue
			}
			violations = append(violations, fmt.Sprintf("%s: %s writes a terminal scan status (%s) without StampScanStatus/SetScanStatus",
				fset.Position(fn.Pos()), fn.Name.Name, strings.Join(writes, ", ")))
		}
	})
	if len(violations) > 0 {
		t.Errorf("terminal scan status written without stamping the row:\n%s", strings.Join(violations, "\n"))
	}
}

// forEachRepoGoFile parses every non-test .go file in the repository and
// hands it to fn with its repo-relative slash path.
func forEachRepoGoFile(t *testing.T, fn func(path string, fset *token.FileSet, file *ast.File)) {
	t.Helper()
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found from internal/db: %v", err)
	}
	fset := token.NewFileSet()
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(rel), fset, file)
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		t.Fatal(err)
	}
}

// governedFieldAssignments flags `x.StatusPriority = ...` / `x.FinishedAt =
// ...` assignments. Only Scan carries fields with these names.
func governedFieldAssignments(fset *token.FileSet, n ast.Node) []string {
	assign, ok := n.(*ast.AssignStmt)
	if !ok {
		return nil
	}
	var out []string
	for _, lhs := range assign.Lhs {
		if sel, ok := lhs.(*ast.SelectorExpr); ok && governedScanFields[sel.Sel.Name] {
			out = append(out, fmt.Sprintf("%s: %s assigned by hand", fset.Position(sel.Pos()), sel.Sel.Name))
		}
	}
	return out
}

// governedScanLiteralKeys flags the governed fields set inside a Scan
// composite literal.
func governedScanLiteralKeys(fset *token.FileSet, n ast.Node) []string {
	lit, ok := n.(*ast.CompositeLit)
	if !ok || !isScanType(lit.Type) {
		return nil
	}
	var out []string
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && governedScanFields[key.Name] {
			out = append(out, fmt.Sprintf("%s: %s set in a Scan literal", fset.Position(kv.Pos()), key.Name))
		}
	}
	return out
}

// governedUpdatesMapKeys flags the governed columns as keys of a map literal
// passed directly to .Updates(...). Only direct arguments are inspected, so
// a "finished_at" key in, say, a JSON payload map is not a violation.
func governedUpdatesMapKeys(fset *token.FileSet, n ast.Node) []string {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	if fun, ok := call.Fun.(*ast.SelectorExpr); !ok || fun.Sel.Name != "Updates" {
		return nil
	}
	lit, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var out []string
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.BasicLit)
		if !ok {
			continue
		}
		if name, err := strconv.Unquote(key.Value); err == nil && governedScanColumns[name] {
			out = append(out, fmt.Sprintf("%s: %q written in an Updates map", fset.Position(kv.Pos()), name))
		}
	}
	return out
}

func isScanType(expr ast.Expr) bool {
	switch typ := expr.(type) {
	case *ast.Ident:
		return typ.Name == "Scan"
	case *ast.SelectorExpr:
		return typ.Sel.Name == "Scan"
	}
	return false
}

var terminalStatusIdents = map[string]bool{
	"ScanDone": true, "ScanFailed": true, "ScanCancelled": true, "ScanSkipped": true,
}

// terminalStatusWrites lists the terminal statuses a function body writes
// into a Status field, by assignment or Scan-literal key.
func terminalStatusWrites(body *ast.BlockStmt) []string {
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			out = append(out, terminalStatusAssignments(node)...)
		case *ast.CompositeLit:
			out = append(out, terminalStatusLiteralKeys(node)...)
		}
		return true
	})
	return out
}

func terminalStatusAssignments(assign *ast.AssignStmt) []string {
	var out []string
	for i, lhs := range assign.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Status" || i >= len(assign.Rhs) {
			continue
		}
		if name := identName(assign.Rhs[i]); terminalStatusIdents[name] {
			out = append(out, name)
		}
	}
	return out
}

func terminalStatusLiteralKeys(lit *ast.CompositeLit) []string {
	if !isScanType(lit.Type) {
		return nil
	}
	var out []string
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Status" {
			continue
		}
		if name := identName(kv.Value); terminalStatusIdents[name] {
			out = append(out, name)
		}
	}
	return out
}

var scanStampHelpers = map[string]bool{"StampScanStatus": true, "SetScanStatus": true}

func callsScanStampHelper(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && scanStampHelpers[identName(call.Fun)] {
			found = true
		}
		return !found
	})
	return found
}

// identName names a bare or package-qualified identifier: ScanDone and
// db.ScanDone both yield "ScanDone".
func identName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}
