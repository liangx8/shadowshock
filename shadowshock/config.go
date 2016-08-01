package shadowshock

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	yaml "gopkg.in/yaml.v2"
)

type (
	Config struct{
		LocalPort string `yaml:"local_port"`
		Servers []ServerInfo `yaml:"servers"`
	}
	ServerInfo struct{
		Description string
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

func (si *ServerInfo)Dial(rawAddr []byte) (net.Conn,error){
	cnn,err := net.Dial("tcp",si.ServerPort)
	if err != nil {
		return nil,err
	}
	dl,err := NewDial(si.Method,si.Password,cnn,si.Ota)
	if err != nil {
		return nil,err
	}
	rw,err:=dl(rawAddr)
	if err != nil { return nil,err}
	return &Conn{
		Conn:cnn,
		read:func(b []byte)(int,error){
			return rw.Read(b)
		},
		write:func(b []byte)(int,error){
			return rw.Write(b)
		},
	},nil
}


