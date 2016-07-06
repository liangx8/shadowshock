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

	key := []byte("windows")

	src,dst := BiPipe()
	csrc,err := ss.NewPipe(method,key,src)
	if err != nil {
		t.Fatal(err)
	}
	cdst,err := ss.NewPipe(method,key,dst)
	if err != nil {
		t.Fatal(err)
	}
	var werr error
	go func(){
		tsrc:=[]byte(text)
		_,werr=csrc.Write(tsrc)
	}()
	tdst := make([]byte, len(text))
	_,err=cdst.Read(tdst)
	if err == nil && werr == nil {
		if isSame(tdst,[]byte(text)) {
			return
		}
		t.Fatal("cipher not same")
	}
	t.Fatal(err,werr)
}

const (
	text = "This is a long test what include 中文"
	method = "des-cfb"
)
