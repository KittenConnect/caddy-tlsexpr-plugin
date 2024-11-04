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
	Expr    string          `json:"expr"`
	Program *exprVM.Program `json:"-"`

	logger *zap.Logger
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
	p.Program = prog

	p.logger.Info("AutoTls Compiled expression : ", zap.String("expr", p.Expr))
	return nil
}

func (p *PermissionByExpr) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	return nil
}

// CertificateAllowed evaluates the expression to determine if a certificate is allowed.
func (p PermissionByExpr) CertificateAllowed(ctx context.Context, name string) error {
	// Evaluate the expression with the domain variable set to the requested name.
	result, err := expr.Run(p.Program, PermissionByExprEnv{
		Domain: name,
	})
	if err != nil {
		return fmt.Errorf("evaluating expression: %v", err)
	}

	if !result.(bool) {
		return fmt.Errorf("%s: %w - permission denied by expression", name, caddytls.ErrPermissionDenied)
	}

	return nil
}

// evaluateExpression evaluates the given expression with the specified domain name.
func evaluateExpression(program *exprVM.Program, domain string) (bool, error) {
	// Create an environment with the domain variable.
	// PermissionByExprEnv
	env := map[string]interface{}{
		"domain": domain,
	}

	fmt.Println(output)

	// Evaluate the expression.
	return output.(bool), nil
}
