package middleware

import (
	"strings"

	"github.com/boqrs/iot-user-perm/pkg/utils"
	logger "github.com/boqrs/zeus/log"
	"github.com/gin-gonic/gin"
)

// JWTAuth JWT认证中间件
func JWTAuth(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从Header获取Token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Errorf("Missing authentication token.")
			c.Abort()
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			log.Errorf("Invalid token format. (Required: Bearer + Token)")
			c.Abort()
			return
		}
		// 解析Token
		claims, err := utils.ParseToken(parts[1])
		if err != nil {
			log.Errorf("Invalid or expired token.")
			c.Abort()
			return
		}
		// 将用户信息存入上下文
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roleCode", claims.RoleCode)
		c.Next()
	}
}
