package auth

import (
    "context"
    "net/http"
)

type contextKey string

const claimsKey contextKey = "claims"

// RequireRole returns middleware that enforces a minimum privilege level.
// Unauthenticated requests are redirected to /login.
// Authenticated requests with insufficient role receive 403.
func (s *Service) RequireRole(minRole string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, err := s.TokenFromRequest(r)
            if err != nil {
                // not logged in → redirect to login, preserve intended destination
                http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusSeeOther)
                return
            }
            if !HasMinRole(claims.Role, minRole) {
                http.Error(w, "403 Forbidden — your role does not have access to this resource.", http.StatusForbidden)
                return
            }
            // Inject claims into context for downstream handlers
            ctx := context.WithValue(r.Context(), claimsKey, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// ClaimsFromContext retrieves the JWT claims stored by RequireRole.
// Returns nil if the context was not set (e.g. on public routes).
func ClaimsFromContext(ctx context.Context) *Claims {
    c, _ := ctx.Value(claimsKey).(*Claims)
    return c
}