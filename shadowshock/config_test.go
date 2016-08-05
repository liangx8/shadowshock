package shadowshock_test

import (
	"testing"
	sh "github.com/liangx8/shadowshock/shadowshock"
)

func Test_config(t *testing.T){
	var cfg,cfg1 sh.Config
	sh.ParseConfig([]byte(text),&cfg)
	if len(cfg.Servers) != 3 {
		t.Fatal("parse array config fail")
	}
	err:=sh.ParseConfig([]byte(text1),&cfg1)
	if err != nil {
		t.Error(err)
	}
	if cfg.Timeout != cfg1.Timeout || cfg.LocalPort != cfg1.LocalPort {
		t.Fatal("parse config test fail")
	}
	for i,s := range cfg.Servers {
		if s.Server != cfg1.Servers[i].Server ||
			s.Method != cfg1.Servers[i].Method ||
			s.Password != cfg1.Servers[i].Password ||
			sses.Name != cfg1.Servers[i].Name {
			t.Fatal("parse config test fail 2")
		}
	}
}


const text =`
timeout: 500
local-port: 1080
servers:
- - "ssserver.com:33443"
  - aes-256-cfb
  - yAd9Eo
  - server 1
- ["ssserver2.com:4423",chacha20,passw0rd,server 2]
- ["ssserver3.com:4423",chacha20,passw0rd,server 3]
`
const text1 =`
timeout: 500
local-port: 1080
servers:
- server: "ssserver.com:33443"
  method: aes-256-cfb
  password: yAd9Eo
  name: server 1
- server: "ssserver2.com:4423"
  method: chacha20
  password: passw0rd
  name: server 2
- server: "ssserver3.com:4423"
  method: chacha20
  password: passw0rd
  name: server 3
`
