package shadowshock

import (
	"fmt"
	"io"
	"io/ioutil"
	yaml "gopkg.in/yaml.v2"
)

type (
	Config struct{
		LocalPort string `yaml:"local_port"`
		Servers []ServerInfo `yaml:"servers"`
	}
	ServerInfo struct{
		ServerPort string `yaml:"server_port"`
		Method string
		Password string
		Ota bool
	}
)

func ParseConfig(r io.Reader) (*Config,error){
	var cfg Config
	cfgBuf,err := ioutil.ReadAll(r)
	if err != nil {
		return nil,err
	}
	err = yaml.Unmarshal(cfgBuf,&cfg)
	if err != nil {
		return nil,err
	}
	for _,s := range cfg.Servers {
		if s.Password == "" {
			return nil,fmt.Errorf("password must be given for server %s",s.ServerPort)
		}
	}
	return &cfg,nil
}

