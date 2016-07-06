package shadowshock

import (
	"io"
	"crypto/rand"
	"crypto/md5"
	"crypto/rc4"
)

type (
	rc4c struct{
		Encrypt
		Decrypt
		ivLen int
		key []byte
	}
)
func (c *rc4c)InitEnc()([]byte,error ){

	iv := make([]byte,c.ivLen)
	if _,err := rand.Read(iv); err != nil {
		return nil,err
	}
	h := md5.New()
	h.Write(c.key)
	h.Write(iv)
	s,err :=rc4.NewCipher(h.Sum(nil))
	if err != nil {
		return nil,err
	}
	c.Encrypt=NewEncrypt(s)
	return iv,nil
}
func (c *rc4c)InitDec(r io.Reader)error{
	iv := make([]byte,c.ivLen)
	if num,err:=r.Read(iv); err != nil {
		if err != io.EOF {
			return err
		}
		if num < c.ivLen {
			return err
		}
	}
	h := md5.New()
	h.Write(c.key)
	h.Write(iv)
	s,err :=rc4.NewCipher(h.Sum(nil))
	if err != nil {
		return err
	}
	c.Decrypt = NewDecrypt(s)
	return nil
}

func rc4Cipher(ivLen int,key []byte)(Cipher,error){
	return &rc4c{ivLen:ivLen,key:key},nil
}
