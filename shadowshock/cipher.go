package shadowshock

import (
	"io"
	"crypto/md5"
	"crypto/cipher"
)


type (
	Cipher struct{
		iv []byte
		blockSize int
		block cipher.Block
		enc,dec cipher.Stream
	}
	Pipe struct{
		io.ReadWriter
		encPipe io.ReadWriter
		buf []byte
		getCipher func()*Cipher
	}
	UnsupportError string
)
func (name UnsupportError) Error() string{
	return "Unsupport method: " + name
}
func (c *Cipher)getIv(b []byte) error{
	if c.iv == nil {
		c.iv = make([]byte,c.blockSize)
		if _,err := rand.Read(c.iv); err != nil {
			return err
		}
	}
	copy(b,c.iv)
	return nil
}
func (t *Cipher)Enc(dst,src []byte) error{
}
func (t *Cipher)Dec(dst,src []byte)error{
}
// key for cipher.Block
// encryptAdaptor for encrypt channel
func NewPipe(encMethod string,key []byte,pipe io.ReadWriter) (*Pipe,error){
	var pp Pipe
	var cip Cipher
	pp.encPipe=pipe
	cinfo,ok := encryptMethod[encMethod]
	if !ok {
		return nil,UnsupportError(encMethod)
	}
	cip.blockSize=cinfo.blockLen
	pp.getCipher=func()(*Cipher,error){
		cip.block,err:=cinfo.createBlock(cinfo.keyLen,key)
		if err != nil {
			return nil,err
		}
		return &cip,nil
	}
	return &pp,nil
}
// Init or Apply a IV before use Cipher
func (p *Pipe)Write(plaintext []byte) (int, error){
	// encode plaintext and write to encPipe
	if p.buf == nil {
		cip,err := p.getCipher()
		if err != nil {
			return 0,err
		}
		p.buf = make([]byte,cip.blockSize+len(plaintext))
		if err = p.getIv(b) ; err != nil {
			return 0,err
		}
	}
	if err=c.Enc(p.buf[cip.blockSize:],plaintext);err != nil {
		return 0,err
	}
	return p.encPipe.Write(c.buf)
}
func (p *Pipe)Read(plaintext []byte) (int,error){
	// read from encryptAdapotr and decode
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
