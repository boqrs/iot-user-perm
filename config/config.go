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
	Grpc   GrpcConfig          `toml:"grpc"`
}

type GrpcConfig struct {
	Host string `toml:"host"`
	Port string `toml:"port"`
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
	p := filepath.Join(dir, "/config/config.toml")
	if _, err = toml.DecodeFile(p, &cfg); err != nil {
		return nil, err
	}
	log.Printf("Get Config info: %#v\n", cfg)
	return &cfg, nil
}
