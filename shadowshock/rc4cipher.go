package shadowshock

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"

	"github.com/codahale/chacha20"
)


func rc4Cipher(key []byte)(*Cipher,error){
	var c Cipher
	
	c.streamMaker=CipherStreamMaker{}
	c.streamMaker.EncryptStream=func(iv []byte)(cipher.Stream,error){
		h := md5.New()
		h.Write(key)
		h.Write(iv)
		return rc4.NewCipher(h.Sum(nil))
	}
	c.streamMaker.DecryptStream=c.streamMaker.EncryptStream
	return &c,nil
}

func chacha20Cipher(key []byte)(*Cipher,error){
	var c Cipher
	c.streamMaker.DecryptStream=func(iv []byte)(cipher.Stream,error){
		return chacha20.New(key,iv)
	}
	c.streamMaker.EncryptStream=c.streamMaker.DecryptStream
	return &c,nil
	
}
