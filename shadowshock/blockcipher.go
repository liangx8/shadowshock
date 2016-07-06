package shadowshock

import (
	"io"
	"crypto/cipher"
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
)

type (
	blockcipher struct{
		ivLen int
		block cipher.Block
		enc,dec cipher.Stream
	}

)

func newblockcipher(ivLen,keyLen int,key []byte,f func([]byte)(cipher.Block,error))(Cipher,error){
	var bc blockcipher
	var err error
	bc.ivLen=ivLen
	rawKey :=GenKey(key,keyLen)
	bc.block,err=f(rawKey)
	if err != nil {
		return nil,err
	}
	return &bc,nil
}
func aesCipher(ivLen,keyLen int,key []byte)(Cipher,error){
	return newblockcipher(ivLen,keyLen,key,aes.NewCipher)
}
func desCipher(ivLen,keyLen int,key []byte)(Cipher,error){
	return newblockcipher(ivLen,keyLen,key,des.NewCipher)
}

func (c *blockcipher)InitEnc()(iv []byte,err error ){
	iv = make([]byte,c.ivLen)
	_,err = rand.Read(iv)
	if err != nil {
		return
	}
	c.enc = cipher.NewCFBEncrypter(c.block,iv)
	return
}
func (c *blockcipher)InitDec(r io.Reader)error{
	iv :=make([]byte,c.ivLen)
	if num,err:=r.Read(iv); err != nil {
		if err != io.EOF {
			return err
		}
		if num < c.ivLen {
			return err
		}
	}
	c.dec = cipher.NewCFBDecrypter(c.block,iv)
	return nil
}
func (c *blockcipher)Enc(dst,src []byte){
	c.enc.XORKeyStream(dst,src)
}
func (c *blockcipher)Dec(dst,src []byte){
	c.dec.XORKeyStream(dst,src)
}
