package shadowshock

import (
	"crypto/md5"
	"crypto/cipher"
	"io"
	"crypto/rand"
)


type (
	Cipher struct{

		blockSize int
		block cipher.Block
		enc,dec cipher.Stream
	}
	Pipe struct{
		io.ReadWriter
		encPipe io.ReadWriter
		// wbuf is nil if first write to
		// rbuf is nil if first recive
		wbuf,rbuf []byte

		cip *Cipher
	}
	UnsupportError string
)
func (name UnsupportError) Error() string{
	return "Unsupport method: " + string(name)
}
func (c *Cipher)initEnc(iv []byte) {
	c.enc = cipher.NewCFBEncrypter(c.block,iv)
}
func (c *Cipher)initDec(iv []byte){
	c.dec = cipher.NewCFBDecrypter(c.block,iv)

}
func (c *Cipher)Enc(dst,src []byte){
	c.enc.XORKeyStream(dst,src)
}
func (c *Cipher)Dec(dst,src []byte){
	c.dec.XORKeyStream(dst,src)
}
// key for cipher.Block
// pipe for encrypt channel
func NewPipe(encMethod string,key []byte,pipe io.ReadWriter) (pp *Pipe,err error){
	var pip Pipe
	var cip Cipher
	pip.encPipe=pipe
	cinfo,ok := encryptMethod[encMethod]
	if !ok {
		return nil,UnsupportError(encMethod)
	}
	cip.blockSize=cinfo.blockLen
	cip.block,err=cinfo.createBlock(cinfo.keyLen,key)
	if err != nil {
		return
	}
	pip.cip=&cip
	pp = &pip
	return 
}
// Init or Apply a IV before use Cipher
func (p *Pipe)Write(plaintext []byte) (int, error){
	// encode plaintext and write to encPipe
	var eob int
	if p.wbuf == nil {
		cip := p.cip
		eob = cip.blockSize+len(plaintext)
		p.wbuf = make([]byte,eob)
		// create a IV
		if _,err := rand.Read(p.wbuf[:cip.blockSize]); err != nil {
			return 0,err
		}
		p.cip.initEnc(p.wbuf[:cip.blockSize])
		p.cip.Enc(p.wbuf[cip.blockSize:],plaintext)
	} else {

		eob = len(plaintext)
		if eob >len(p.wbuf) {
			p.wbuf = make([]byte,eob)
		}
		p.cip.Enc(p.wbuf,plaintext)
	}
	return p.encPipe.Write(p.wbuf[:eob])
}
func (p *Pipe)Read(plaintext []byte) (int,error){
	// read from encPipe and decode
	eob := len(plaintext)
	if p.rbuf == nil {
		p.rbuf = make([]byte, p.cip.blockSize)
		// read IV from sender
		if _,err := p.encPipe.Read(p.rbuf);err != nil{
			return 0,err
		}
		p.cip.initDec(p.rbuf)
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


const (
	AES32 = "aes-256-cfb"
	AES24 = "aes-192-cfb"
	AES16 = "aes-128-cfb"
)
