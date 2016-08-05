package shadowshock

import (
	yaml "gopkg.in/yaml.v2"
)

type (
	Config struct {
		Timeout int
		LocalPort string `yaml:"local-port"`
		Servers []ServerInfo
	}
	ServerInfo struct {
		Name, Server, Method, Password string
		Ota bool
	}
)
func ParseConfig(buf []byte,cfg *Config) error{
	var arrCfg struct {
		Timeout int
		LocalPort string `yaml:"local-port"`
		Servers [][]string
		
	}
	yaml.Unmarshal(buf,&arrCfg)
	if cnt := len(arrCfg.Servers); cnt > 0 {
		svrs := make([]ServerInfo,0)
		for _,a := range arrCfg.Servers {
			if col := len(a) ; col == 4 {
				var svr ServerInfo
				svr.Server   = a[0]
				svr.Method   = a[1]
				svr.Password = a[2]
				svr.Name     = a[3]
				svrs = append(svrs,svr)
			}
		}
		if len(svrs) > 0 {
			cfg.Timeout=arrCfg.Timeout
			cfg.LocalPort=arrCfg.LocalPort
			cfg.Servers=svrs
			return nil
		}
	}
	return yaml.Unmarshal(buf,cfg)
}
