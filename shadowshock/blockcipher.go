package shadowshock

import (

	"crypto/cipher"
	"crypto/aes"
	"crypto/des"
)


func newblockcipher(ivLen int,key []byte,f func([]byte)(cipher.Block,error))(*Cipher,error){
	var c Cipher
	c.ivLen=ivLen
	block,err:=f(key)
	if err != nil {
		return nil,err
	}
	c.dec=func(iv []byte)(cipher.Stream,error){
		return cipher.NewCFBDecrypter(block,iv),nil
	}
	c.enc=func(iv []byte)(cipher.Stream,error){
		return cipher.NewCFBEncrypter(block,iv),nil
	}
	return &c,nil
}
func aesCipher(ivLen int,key []byte)(*Cipher,error){
	return newblockcipher(ivLen,key,aes.NewCipher)
}
func desCipher(ivLen int,key []byte)(*Cipher,error){
	return newblockcipher(ivLen,key,des.NewCipher)
}
