package shadowshock

import (
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

var encryptMethod = map[string]CipherInfo{
	AES32:{aes.BlockSize,32,aesBlock},
	AES24:{aes.BlockSize,24,aesBlock},
	AES16:{aes.BlockSize,16,aesBlock},
}
