package shadowshock

import (
	"crypto/des"
	"crypto/aes"
	"crypto/cipher"
)
type (
	CipherInfo struct{
		blockLen,keyLen int
		createBlock func(int,[]byte) (cipher.Block,error)
	}
)
func aesBlock(size int,key []byte) (cipher.Block,error){
	rawKey:=GenKey(key,size)
	return aes.NewCipher(rawKey)
}

func desBlock(size int,key []byte) (cipher.Block,error){
	rawKey:=GenKey(key,size)
	return des.NewCipher(rawKey) 
}
var encryptMethod = map[string]CipherInfo{
	AES32:{aes.BlockSize,32,aesBlock},
	AES24:{aes.BlockSize,24,aesBlock},
	AES16:{aes.BlockSize,16,aesBlock},
	DES:{8,8,desBlock},
}

const (
	AES32 = "aes-256-cfb"
	AES24 = "aes-192-cfb"
	AES16 = "aes-128-cfb"
	DES   = "des-cfb"
)
