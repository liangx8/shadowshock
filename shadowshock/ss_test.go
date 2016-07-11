package shadowshock_test

import (
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	sh "github.com/liangx8/shadowshock/shadowshock"
	"testing"
	"net"
)
func Test_meet_ss_ota(t *testing.T){
}
func Test_meet_ss(t *testing.T){
	meet_ss("aes-256-cfb",t)
	meet_ss("aes-192-cfb",t)
	meet_ss("aes-128-cfb",t)
	meet_ss("des-cfb",t)
}
func meet_ss(method string,t *testing.T){

	cherr := make(chan error)
	go func(){

		conn,err :=net.Dial("tcp","127.0.0.1:12080")
		if err != nil {
			cherr <- err
			return
		}
		defer conn.Close()
		cip,err :=ss.NewCipher(method,pwd)
		if err != nil {
			cherr <- err
			return
		}
		cconn := ss.NewConn(conn,cip)
		_,err=cconn.Write([]byte(text))
		if err != nil {
			cherr <- err
			return
		}

	}()
	out := make([]byte,len(text))
	go func(){
		ltn,err := net.Listen("tcp","127.0.0.1:12080")
		if err != nil {
			cherr <- err
			return
		}
		defer ltn.Close()
		cc,err := ltn.Accept()
		if err != nil {
			cherr <- err
			return
		}
		defer cc.Close()
		pip,err:=sh.NewReadWriter(method,[]byte(pwd),cc,sh.EncryptIo)
		if err != nil{
			cherr <- err
			return
		}
		pip.Read(out)
		close(cherr)
	}()
	err := <- cherr
	if err != nil {
		t.Fatal(err)
	}
	if isSame(out,[]byte(text)) {
		return
	}
	t.Fatalf("%s cipher not same",method)
	
}


const (

	pwd = "windows"
)
