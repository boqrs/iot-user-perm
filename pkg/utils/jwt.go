package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// JWTSecret JWT密钥（部署时替换为环境变量）
var JWTSecret = []byte("permission_admin_jwt_secret_2026")

// Claims JWT载荷
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	RoleCode string `json:"role_code"`
	jwt.RegisteredClaims
}

// GenerateToken 生成JWT Token
func GenerateToken(userID, username, roleCode string) (string, error) {
	expireTime := time.Now().Add(2 * time.Hour) // 2小时过期
	claims := Claims{
		UserID:   userID,
		Username: username,
		RoleCode: roleCode,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "permission-admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JWTSecret)
}

// ParseToken 解析JWT Token
func ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrSignatureInvalid
}
