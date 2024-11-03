
package caddyPlugin 

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(PermissionByExpr{})
}


// PermissionByExpr determines permission for a TLS certificate by
// making a request to an HTTP endpoint.
type PermissionByExpr struct {
	// The endpoint to access. It should be a full URL.
	// A query string parameter "domain" will be added to it,
	// containing the domain (or IP) for the desired certificate,
	// like so: `?domain=example.com`. Generally, this endpoint
	// is not exposed publicly to avoid a minor information leak
	// (which domains are serviced by your application).
	//
	// The endpoint must return a 200 OK status if a certificate
	// is allowed; anything else will cause it to be denied.
	// Redirects are not followed.
	Endpoint string `json:"endpoint"`

	logger   *zap.Logger
	replacer *caddy.Replacer
}

// CaddyModule returns the Caddy module information.
func (PermissionByExpr) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.http",
		New: func() caddy.Module { return new(PermissionByExpr) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *PermissionByExpr) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return nil
	}
	if !d.AllArgs(&p.Endpoint) {
		return d.ArgErr()
	}
	return nil
}

func (p *PermissionByExpr) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	p.replacer = caddy.NewReplacer()
	return nil
}

func (p PermissionByExpr) CertificateAllowed(ctx context.Context, name string) error {
	// run replacer on endpoint URL (for environment variables) -- return errors to prevent surprises (#5036)
	askEndpoint, err := p.replacer.ReplaceOrErr(p.Endpoint, true, true)
	if err != nil {
		return fmt.Errorf("preparing 'ask' endpoint: %v", err)
	}

	askURL, err := url.Parse(askEndpoint)
	if err != nil {
		return fmt.Errorf("parsing ask URL: %v", err)
	}
	qs := askURL.Query()
	qs.Set("domain", name)
	askURL.RawQuery = qs.Encode()
	askURLString := askURL.String()

	var remote string
	if chi, ok := ctx.Value(certmagic.ClientHelloInfoCtxKey).(*tls.ClientHelloInfo); ok && chi != nil {
		remote = chi.Conn.RemoteAddr().String()
	}

	p.logger.Debug("asking permission endpoint",
		zap.String("remote", remote),
		zap.String("domain", name),
		zap.String("url", askURLString))

	resp, err := onDemandAskClient.Get(askURLString)
	if err != nil {
		return fmt.Errorf("checking %v to determine if certificate for hostname '%s' should be allowed: %v",
			askEndpoint, name, err)
	}
	resp.Body.Close()

	p.logger.Debug("response from permission endpoint",
		zap.String("remote", remote),
		zap.String("domain", name),
		zap.String("url", askURLString),
		zap.Int("status", resp.StatusCode))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: %w %s - non-2xx status code %d", name, ErrPermissionDenied, askEndpoint, resp.StatusCode)
	}

	return nil
}

// These perpetual values are used for on-demand TLS.
var (
	onDemandRateLimiter = certmagic.NewRateLimiter(0, 0)
	onDemandAskClient   = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("following http redirects is not allowed")
		},
	}
)

// Interface guards
var (
	_ OnDemandPermission = (*PermissionByExpr)(nil)
	_ caddy.Provisioner  = (*PermissionByExpr)(nil)
)
