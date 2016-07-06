package shadowshock

import (

	"io"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
)


type (
	Cipher struct{
		ivLen int
		enc,dec func([]byte) (cipher.Stream,error)
	}
	Pipe struct{
		r *cipher.StreamReader
		w *cipher.StreamWriter
		cip *Cipher
	}
	UnsupportError string
)
func (name UnsupportError) Error() string{
	return "Unsupport method: " + string(name)
}

func NewPipe(encMethod string,key []byte,pipe io.ReadWriter) (*Pipe,error){
	var pip Pipe
	var err error
	cinfo,ok := encryptMethod[encMethod]
	if !ok {
		return nil,UnsupportError(encMethod)
	}
	rawKey := GenKey(key,cinfo.keyLen)
	pip.cip,err=cinfo.newCipher(cinfo.ivLen,rawKey)
	if err != nil {
		return nil,err
	}
	pip.r=&cipher.StreamReader{S:nil,R:pipe}
	pip.w=&cipher.StreamWriter{S:nil,W:pipe}
	return &pip,nil

}
// Init or Apply a IV before use Cipher
func (p *Pipe)Write(plaintext []byte) (int, error){
	if p.w.S == nil {
		var err error
		iv := make([]byte,p.cip.ivLen)
		_,err = rand.Read(iv)
		if err != nil {
			return 0,err
		}
		p.w.S,err=p.cip.enc(iv)
		if err != nil {
			return 0,err
		}
		_,err=p.w.W.Write(iv)
		if err != nil {
			return 0,err
		}
	}
	return p.w.Write(plaintext)
}
func (p *Pipe)Read(plaintext []byte) (int,error){
	var err error
	if p.r.S == nil {

		iv := make([]byte,p.cip.ivLen)
		if _,err = p.r.R.Read(iv); err != nil {
			return 0,err
		}
		p.r.S,err=p.cip.dec(iv)
		if err != nil {
			return 0,err
		}
	}
	return p.r.Read(plaintext)
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

