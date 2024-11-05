package caddytlsexpr

import (
	"context"
	"fmt"

	// "strings"

	// "github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"

	"github.com/expr-lang/expr"
	exprVM "github.com/expr-lang/expr/vm"
)

func init() {
	caddy.RegisterModule(PermissionByExpr{})
}

type PermissionByExprEnv struct {
	Domain string
}

// PermissionByExpr determines permission for a TLS certificate by evaluating an expression.
type PermissionByExpr struct {
	// The expression to evaluate for permission.
	// It should use "domain" as a variable, for example: "domain == 'example.com'".
	Expr string `json:"expr"`

	program *exprVM.Program `json:"-"`
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (PermissionByExpr) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.expr",
		New: func() caddy.Module { return new(PermissionByExpr) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *PermissionByExpr) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return nil
	}

	if !d.AllArgs(&p.Expr) {
		return d.ArgErr()
	}

	prog, err := expr.Compile(p.Expr, expr.Env(PermissionByExprEnv{}))
	if err != nil {
		return (err)
	}
	p.program = prog

	return nil
}

func (p *PermissionByExpr) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	return nil
}

// CertificateAllowed evaluates the expression to determine if a certificate is allowed.
func (p PermissionByExpr) CertificateAllowed(ctx context.Context, name string) error {
	// Evaluate the expression with the domain variable set to the requested name.
	result, err := expr.Run(p.program, PermissionByExprEnv{
		Domain: name,
	})

	// fmt.Printf("%s", )

	if err != nil {
		return fmt.Errorf("evaluating expression: %v", err)
	}

	switch v := result.(type) {
	case bool:
		if !v {
			return fmt.Errorf("%s: %w - permission denied by expression", name, caddytls.ErrPermissionDenied)
		}

	default:
		return fmt.Errorf("%s: %w - Unknown type %T for expression result - permission denied by expression", name, caddytls.ErrPermissionDenied, v)
		// no match; here v has the same type as i
	}

	return nil
}
