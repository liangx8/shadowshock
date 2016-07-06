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
		Encrypt
		Decrypt
		ivLen int
		block cipher.Block
	}

)

func newblockcipher(ivLen int,key []byte,f func([]byte)(cipher.Block,error))(Cipher,error){
	var bc blockcipher
	var err error
	bc.ivLen=ivLen
	bc.block,err=f(key)
	if err != nil {
		return nil,err
	}
	return &bc,nil
}
func aesCipher(ivLen int,key []byte)(Cipher,error){
	return newblockcipher(ivLen,key,aes.NewCipher)
}
func desCipher(ivLen int,key []byte)(Cipher,error){
	return newblockcipher(ivLen,key,des.NewCipher)
}

func (c *blockcipher)InitEnc()(iv []byte,err error ){
	iv = make([]byte,c.ivLen)
	_,err = rand.Read(iv)
	if err != nil {
		return
	}
	c.Encrypt=NewEncrypt(cipher.NewCFBEncrypter(c.block,iv))

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
	c.Decrypt=NewDecrypt(cipher.NewCFBDecrypter(c.block,iv))
	return nil
}
