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
	Domain string `expr:"domain"`
	// Remote string `expr:"domain"` // UseLess

	logger *zap.Logger
}

func (env *PermissionByExprEnv) Info(msg string) {
	env.logger.Info(msg)
}

// PermissionByExpr determines permission for a TLS certificate by evaluating an expression.
type PermissionByExpr struct {
	// The expression to evaluate for permission.
	// It should use "domain" as a variable, for example: "domain == 'example.com'".
	Expr string `json:"expr"`

	program *exprVM.Program
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
		return err
	}
	p.program = prog

	if p.logger != nil {
		p.logger.Info("AutoTLS Compiled expr for later usage", zap.String("expr", p.Expr))
	} else {
		fmt.Printf("AutoTLS Compiled expr for later usage: %s", p.Expr)
	}

	return nil
}

func (p *PermissionByExpr) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger().With(zap.String("autotls_expr", p.Expr))

	return nil
}

// CertificateAllowed evaluates the expression to determine if a certificate is allowed.
func (p PermissionByExpr) CertificateAllowed(ctx context.Context, name string) error {
	if p.program == nil {
		prog, err := expr.Compile(p.Expr, expr.Env(PermissionByExprEnv{}))
		if err != nil {
			return err
		}
		p.program = prog
	}

	// Evaluate the expression with the domain variable set to the requested name.
	result, err := expr.Run(p.program, PermissionByExprEnv{
		Domain: name,

		logger: p.logger.With(zap.String("domain", name)),
	})

	// fmt.Printf("%s", )

	if err != nil {
		return fmt.Errorf("evaluating expression: %w", err)
	}

	switch v := result.(type) {
	case bool:
		if v {
			return nil
		} else {
			return fmt.Errorf("%s: %w - permission denied by expression", name, caddytls.ErrPermissionDenied)
		}

	default:
		return fmt.Errorf("%s: %w - Unknown type %T for expression result - permission denied by expression", name, caddytls.ErrPermissionDenied, v)
		// no match; here v has the same type as i
	}

	// Should never go here
}
