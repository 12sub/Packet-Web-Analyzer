package auth

import (
    "errors"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

const (
    RoleUser   = "user"
    RoleEditor = "editor"
    RoleAdmin  = "admin"

    cookieName = "pa_token"
    jwtExpiry  = 24 * time.Hour
)

// roleLevel defines the privilege hierarchy.
var roleLevel = map[string]int{
    RoleUser:   1,
    RoleEditor: 2,
    RoleAdmin:  3,
}

// Claims are embedded in every JWT.
type Claims struct {
    UserID   int64  `json:"uid"`
    Username string `json:"sub"`
    Role     string `json:"role"`
    jwt.RegisteredClaims
}

type Service struct{ secret []byte }

func NewService(secret string) *Service {
    return &Service{secret: []byte(secret)}
}

// HashPassword returns a bcrypt hash of the plaintext password.
func (s *Service) HashPassword(password string) (string, error) {
    b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(b), err
}

// CheckPassword reports whether password matches the stored hash.
func (s *Service) CheckPassword(hash, password string) bool {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// IssueToken creates and signs a JWT for the given user.
func (s *Service) IssueToken(userID int64, username, role string) (string, error) {
    claims := Claims{
        UserID:   userID,
        Username: username,
        Role:     role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

// ValidateToken parses and validates a JWT string.
func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return s.secret, nil
    })
    if err != nil {
        return nil, err
    }
    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, errors.New("invalid token")
    }
    return claims, nil
}

// SetCookie writes the JWT into an HttpOnly, SameSite=Strict cookie.
func (s *Service) SetCookie(w http.ResponseWriter, token string) {
    http.SetCookie(w, &http.Cookie{
        Name:     cookieName,
        Value:    token,
        Path:     "/",
        HttpOnly: true,                    // JS cannot access this cookie
        SameSite: http.SameSiteStrictMode, // CSRF protection
        MaxAge:   int(jwtExpiry.Seconds()),
    })
}

// ClearCookie expires the session cookie.
func (s *Service) ClearCookie(w http.ResponseWriter) {
    http.SetCookie(w, &http.Cookie{
        Name:   cookieName,
        Value:  "",
        Path:   "/",
        MaxAge: -1,
    })
}

// TokenFromRequest extracts and validates the JWT from the request cookie.
func (s *Service) TokenFromRequest(r *http.Request) (*Claims, error) {
    cookie, err := r.Cookie(cookieName)
    if err != nil {
        return nil, errors.New("no session cookie")
    }
    return s.ValidateToken(cookie.Value)
}

// HasMinRole reports whether userRole meets the minimum required role.
func HasMinRole(userRole, minRole string) bool {
    return roleLevel[userRole] >= roleLevel[minRole]
}