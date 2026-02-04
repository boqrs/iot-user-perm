package rpc

type DeviceVO struct {
	DeviceId     string `json:"device_id"`
	Model        string `json:"model"`
	Firmware     string `json:"firmware"`
	OnlineStatus string `json:"online_status"`
	PermType     string `json:"perm_type"`
}

type UserDeviceItem struct {
	DeviceID string `gorm:"column:device_id" json:"device_id"`
	PermType string `gorm:"column:perm_type" json:"perm_type"`
}

type DevicePermUserItem struct {
	UserID   string `gorm:"column:user_id" json:"user_id"`
	PermType string `gorm:"column:perm_type" json:"perm_type"`
}
