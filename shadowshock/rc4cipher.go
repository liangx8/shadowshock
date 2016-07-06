package shadowshock

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"

	"github.com/codahale/chacha20"
)


func rc4Cipher(ivLen int,key []byte)(*Cipher,error){
	var c Cipher
	c.ivLen=ivLen
	c.dec=func(iv []byte)(cipher.Stream,error){
		h := md5.New()
		h.Write(key)
		h.Write(iv)
		return rc4.NewCipher(h.Sum(nil))
	}
	c.enc=c.dec
	return &c,nil
}

func chacha20Cipher(ivLen int,key []byte)(*Cipher,error){
	var c Cipher
	c.ivLen=ivLen
	c.dec=func(iv []byte)(cipher.Stream,error){
		return chacha20.New(key,iv)
	}
	c.enc=c.dec
	return &c,nil
	
}
