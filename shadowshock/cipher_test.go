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
		defer dst.Close()

		cdst,rawAddr,err := ss.Service(method,key,dst)
		if err != nil {
			t.Error(err)
			return
		}
		if !isSame(testRawAddr,rawAddr){
			t.Error("raw address is not expected!")
			return
		}
		_,err=io.Copy(cdst,cdst)
		if err != nil {
			t.Error(err)
			return
		}
	}()

	dl,err := ss.NewDial(method,key,src,false)
	if err != nil {
		t.Fatal(err)
	}
	csrc,err :=dl(testRawAddr)
	if err != nil {
		t.Fatal(err)
	}

	go func(){

		_,err =csrc.Write([]byte(text))
		if err != nil {
			t.Fatal(err)
		}

	}()
	buf:=make([]byte,len(text))
	_,err = csrc.Read(buf)
	if err != nil { t.Fatal(err)}

	if isSame(buf,[]byte(text)) {
		return
	}
	t.Fatalf("%s cipher not same",method)
}

const (
	text        = "This is a long test what include 中文"
	rettext     = "It's OK"
	testRawAddr = []byte{ 3,0,0,0 }
)
