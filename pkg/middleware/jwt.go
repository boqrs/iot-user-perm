package middleware

import (
	"strings"

	"github.com/boqrs/iot-user-perm/pkg/utils"
	"github.com/gin-gonic/gin"
)

// JWTAuth JWT认证中间件
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从Header获取Token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.Fail(c, utils.ErrCodeUnauth, "未携带认证Token")
			c.Abort()
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			utils.Fail(c, utils.ErrCodeUnauth, "Token格式错误（需Bearer + Token）")
			c.Abort()
			return
		}
		// 解析Token
		claims, err := utils.ParseToken(parts[1])
		if err != nil {
			utils.Fail(c, utils.ErrCodeUnauth, "Token无效或已过期")
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
