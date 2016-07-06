package shadowshock

import (
	"crypto/md5"
	"io"

)


type (
	Cipher interface{
		// return IV for sending to remote host later
		InitEnc()([]byte,error)
		// read IV from connection
		InitDec(io.Reader) error
		// panic if invoke before first call InitEnc
		Enc(dst,src []byte)
		Dec(dst,src []byte)
	}
	Pipe struct{
		io.ReadWriter
		encPipe io.ReadWriter
		// wbuf is nil if first write to
		// rbuf is nil if first recive
		wbuf,rbuf []byte

		cip Cipher
	}
	UnsupportError string
)
func (name UnsupportError) Error() string{
	return "Unsupport method: " + string(name)
}
// key for cipher.Block
// pipe for encrypt channel
func NewPipe(encMethod string,key []byte,pipe io.ReadWriter) (pp *Pipe,err error){
	var pip Pipe

	pip.encPipe=pipe
	cinfo,ok := encryptMethod[encMethod]
	if !ok {
		return nil,UnsupportError(encMethod)
	}

	pip.cip,err=cinfo.newCipher(cinfo.ivLen,cinfo.keyLen,key)
	if err != nil {
		return
	}

	pp = &pip
	return 
}
// Init or Apply a IV before use Cipher
func (p *Pipe)Write(plaintext []byte) (int, error){
	// encode plaintext and write to encPipe
	eob := len(plaintext)
	if p.wbuf == nil {
		iv,err:=p.cip.InitEnc()
		if err != nil {
			return 0,err
		}
		_,err=p.encPipe.Write(iv)
		if err != nil {
			return 0,err
		}
		p.wbuf=make([]byte,eob)
	}

	if eob >len(p.wbuf) {
		p.wbuf = make([]byte,eob)
	}
	p.cip.Enc(p.wbuf,plaintext)
	return p.encPipe.Write(p.wbuf[:eob])
}
func (p *Pipe)Read(plaintext []byte) (int,error){
	// read from encPipe and decode
	eob := len(plaintext)
	if p.rbuf == nil {
		if err := p.cip.InitDec(p.encPipe); err != nil {
			return 0,err
		}
		p.rbuf=make([]byte,eob)
	}
	if eob > len(p.rbuf) {
		p.rbuf = make([]byte,eob)
	}
	if n,err := p.encPipe.Read(p.rbuf[:eob]); err != nil {
		if err == io.EOF {
			eob = n
		} else {
			return 0,err
		}
	}
	p.cip.Dec(plaintext,p.rbuf[:eob])
	return eob,nil
}
func GenKey(rawKey []byte,size int) []byte{
	h := md5.New()
	const md5len = 16
	md5sum := func(in []byte) []byte{
		h.Reset()
		h.Write(in)
		return h.Sum(nil)
	}
	blkcnt := (size-1) / md5len + 1
	key := make([]byte,blkcnt * md5len)
	nextkey := make([]byte,md5len+len(rawKey))
	copy(key[:md5len],md5sum(rawKey))
	
	copy(nextkey[md5len:],rawKey)
	for i:=1;i<blkcnt;i++ {
		pos := (i-1) * md5len
		copy(nextkey,key[pos:pos+md5len])
		copy(key[pos+md5len:],md5sum(nextkey))
	}
	return key[:size]
}

