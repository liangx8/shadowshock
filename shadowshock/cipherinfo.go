package shadowshock

import (
	"crypto/aes"
)
type (
	CipherInfo struct{
		ivLen,keyLen int
		newCipher func(int,[]byte) (*Cipher,error)
	}
)

var encryptMethod = map[string]CipherInfo{
	AES32:  {aes.BlockSize,32,aesCipher},
	AES24:  {aes.BlockSize,24,aesCipher},
	AES16:  {aes.BlockSize,16,aesCipher},
	DES:    {8,8,desCipher},
	RC4MD5: {16,16,rc4Cipher},
	CHACHA: {8,32,chacha20Cipher},
}

const (
	AES32 = "aes-256-cfb"
	AES24 = "aes-192-cfb"
	AES16 = "aes-128-cfb"
	DES   = "des-cfb"
	RC4MD5 = "rc4-md5"
	CHACHA = "chacha20"
)
