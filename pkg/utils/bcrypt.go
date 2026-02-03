package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// BcryptEncrypt 密码加密
func BcryptEncrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// BcryptVerify 密码验证
func BcryptVerify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// CheckPasswordComplexity 校验密码复杂度（8位+大小写+数字+特殊符）
func CheckPasswordComplexity(password string) bool {
	if len(password) < 8 {
		return false
	}
	var hasUpper, hasLower, hasNum, hasSpecial bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasNum = true
		case c >= 33 && c <= 47 || c >= 58 && c <= 64 || c >= 91 && c <= 96 || c >= 123 && c <= 126:
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasNum && hasSpecial
}
