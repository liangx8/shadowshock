package shadowshock

import (
	"crypto/aes"
)
type (
	CipherInfo struct{
		ivLen,keyLen int
		newCipher func(int,int,[]byte) (Cipher,error)
	}
)

var encryptMethod = map[string]CipherInfo{
	AES32:{aes.BlockSize,32,aesCipher},
	AES24:{aes.BlockSize,24,aesCipher},
	AES16:{aes.BlockSize,16,aesCipher},
	DES:{8,8,desCipher},
}

const (
	AES32 = "aes-256-cfb"
	AES24 = "aes-192-cfb"
	AES16 = "aes-128-cfb"
	DES   = "des-cfb"
)
