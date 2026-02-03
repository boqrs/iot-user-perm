package middleware

import (
	logger "github.com/boqrs/zeus/log"
	"github.com/gin-gonic/gin"
)

// SuperAdminAuth 仅超级管理员可访问
func SuperAdminAuth(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleCode, exists := c.Get("roleCode")
		if !exists || roleCode != "SUPER_ADMIN" {
			log.Errorf("This action requires super administrator privileges.")
			c.Abort()
			return
		}
		c.Next()
	}
}

// AdminAuth 管理员/超级管理员可访问
func AdminAuth(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleCode, exists := c.Get("roleCode")
		if !exists || (roleCode != "SUPER_ADMIN" && roleCode != "ADMIN") {
			log.Error("Operation not permitted.")
			c.Abort()
			return
		}
		c.Next()
	}
}
