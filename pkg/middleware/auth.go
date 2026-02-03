package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// SuperAdminAuth 仅超级管理员可访问
func SuperAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleCode, exists := c.Get("roleCode")
		if !exists || roleCode != "SUPER_ADMIN" {
			fmt.Println("仅超级管理员可操作")
			c.Abort()
			return
		}
		c.Next()
	}
}

// AdminAuth 管理员/超级管理员可访问
func AdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleCode, exists := c.Get("roleCode")
		if !exists || (roleCode != "SUPER_ADMIN" && roleCode != "ADMIN") {
			fmt.Println("无权限操作")
			c.Abort()
			return
		}
		c.Next()
	}
}
