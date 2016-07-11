package shadowshock_test

import (

	"testing"
	ss "github.com/liangx8/shadowshock/shadowshock"
	"io"

)
type rw struct{
	io.Reader
	io.Writer
}
func BiPipe() (src,dst io.ReadWriter){
	srcr,dstw :=io.Pipe()
	dstr,srcw :=io.Pipe()
	src = &rw{srcr,srcw}
	dst = &rw{dstr,dstw}
	return 
}
func isSame(src,dst []byte) (ok bool){
	ok = false
	if len(src) != len(dst) { return }
	for i,b := range src {
		if dst[i] != b {
			return
		}
	}
	return true
}
func Test_pipe(t *testing.T){
	cherr := make(chan error)
	src,dst := BiPipe()
	go func(){
		tsrc := []byte(text)
		_,err := src.Write(tsrc)
		if err != nil {
			cherr <- err
			return
		}
		close(cherr)
	}()
	tdst := make([]byte,len(text))
	_,err:=dst.Read(tdst)
	if err != nil {
		t.Fatal(err)
	}
	err = <-cherr
	if err !=nil {
		t.Fatal(err)
	}
	if isSame(tdst,[]byte(text)) {
		return
	}
	t.Fatal("not same")

}
func Test_cipher(t *testing.T){
	cipher_test("aes-128-cfb",t)
	cipher_test("aes-192-cfb",t)
	cipher_test("aes-256-cfb",t)
	cipher_test("des-cfb",t)
	cipher_test("rc4-md5",t)
	cipher_test("chacha20",t)
	
}

func cipher_test(method string, t *testing.T){
	key := []byte("windows")
	src,dst := BiPipe()
	go func(){
		csrc,err := ss.NewReadWriter(method,key,src,ss.EncryptIo)
		if err != nil {
			panic(err)
		}
		_,err=csrc.Write([]byte(text))
		if err != nil {panic(err)}
		buf := make([]byte,len(rettext))
		_,err = csrc.Read(buf)
		if err != nil {panic(err)}
		if !isSame(buf,[]byte(rettext)) {
			panic(method + " cipher return is not same")
		}
	}()
	tdst := make([]byte, len(text))
	cdst,err := ss.NewReadWriter(method,key,dst,ss.EncryptIo)
	if err != nil {panic(err)}
	_,err =cdst.Read(tdst)
	if err != nil {
		t.Fatal(err)
	}
	_,err = cdst.Write([]byte(rettext))
	if err != nil { t.Fatal(err)}
	if isSame(tdst,[]byte(text)) {
		return
	}
	t.Fatalf("%s cipher not same",method)
}

const (
	text = "This is a long test what include 中文"
	rettext="It's OK"
)
