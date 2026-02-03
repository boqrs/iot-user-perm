package config

import (
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/boqrs/comm/config"
)

type Config struct {
	Redis  config.RedisConfig  `toml:"redis"`
	Sql    config.SqlConfig    `toml:"sql"`
	Log    config.LogConfig    `toml:"log"`
	Con    config.SqlConConfig `toml:"sqlCon"`
	Global GlobalConfig        `toml:"global"`
	Jp     config.JPushCfg     `toml:"jpush"`
	Email  Email               `toml:"email"`
	S3     s3Config            `toml:"s3"`
}

type Email struct {
	Server   string `toml:"server"`
	UserName string `toml:"user_name"`
	Password string `toml:"password"`
}

type s3Config struct {
	Endpoint      string `json:"endpoint"`
	BucketName    string `json:"bucket_name"`
	RootAccessKey string `json:"root_access_key"`
	RootSecretKey string `json:"root_secret_key"`
	ExpireSeconds int64  `json:"expire_seconds"`
}

type GlobalConfig struct {
	Env          string `toml:"env"`
	AuthEndpoint string `toml:"auth_endpoint"`
	ActiveSecret string `toml:"active_secret"`
}

func GetConfig() (*Config, error) {

	cfg := Config{}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	p := filepath.Join(dir, "/config/user.toml")
	if _, err = toml.DecodeFile(p, &cfg); err != nil {
		return nil, err
	}
	log.Printf("Get Config info: %#v\n", cfg)
	return &cfg, nil
}
