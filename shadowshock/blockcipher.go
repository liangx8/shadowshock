package shadowshock

import (

	"crypto/cipher"
	"crypto/aes"
	"crypto/des"
)

func newblockcipher(key []byte,f func([]byte)(cipher.Block,error))(*Cipher,error){
	var c Cipher
	block,err:=f(key)
	if err != nil {
		return nil,err
	}
	c.streamMaker=CipherStreamMaker{}
	c.streamMaker.EncryptStream=func(iv []byte)(cipher.Stream,error){
		return cipher.NewCFBDecrypter(block,iv),nil
	}
	c.streamMaker.DecryptStream=func(iv []byte)(cipher.Stream,error){
		return cipher.NewCFBEncrypter(block,iv),nil
	}
	return &c,nil
}
func aesCipher(key []byte)(*Cipher,error){
	return newblockcipher(key,aes.NewCipher)
}
func desCipher(key []byte)(*Cipher,error){
	return newblockcipher(key,des.NewCipher)
}
