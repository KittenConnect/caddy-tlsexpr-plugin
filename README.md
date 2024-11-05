# caddy-autotls-expr
CAddy2 Plugin allowing usage of expr in auto_tls permission

# Usage
```
        on_demand_tls {
                # permission http http://127.0.0.1:8404/ 

                # Or us Go-Expr
                permission expr <<EOF
                    /* Domain == "example.com" */
                    /* domain is subdomain of these lists */
                    any(
                        [".example.com", ".example.net"],
                        hasSuffix(domain, #)
                        )
                EOF
        }

```
