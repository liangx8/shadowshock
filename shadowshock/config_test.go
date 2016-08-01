package shadowshock_test

import (
	"testing"
	"bytes"
	ss "github.com/liangx8/shadowshock/shadowshock"
)

func Test_config(t *testing.T){
	cfg,err := ss.ParseConfig(bytes.NewBufferString(dummy_config))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LocalPort != "127.0.0.1:1080" {
		t.Fatal("Test config failed!")
	}
	if cfg.Servers[0].ServerPort != "1.2.3.4:4455" {
		t.Fatal("Test config failed!")
	}
	if cfg.Servers[0].Ota == true {
		t.Fatal("Test config failed!")
	}
	if cfg.Servers[1].Ota == false{
		t.Fatal("Test config failed!")
	}
}
const dummy_config =`
local_port: "127.0.0.1:1080"
servers:
# this is first comment
 - server_port: "1.2.3.4:4455"
   method: aes-256-cfb
   password: windows
   ota: no
   description: server 1
# this is second comment
 - server_port: "4.3.2.1:5544"
   method: rc4-md5
   password: window
   ota: yes
   description: server 2
 - server_port: "domain.com:5540"
   password: 123
`
