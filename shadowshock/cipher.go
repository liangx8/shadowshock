package shadowshock

import (

	"io"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
)


type (
	Cipher struct{
		ivLen int
		enc,dec func([]byte) (cipher.Stream,error)
	}
	filterReader func(buf []byte,r io.Reader) (int,error)
	filterWriter func(buf []byte,w io.Writer) (int,error)
	cipherReadWriter struct{
		baseIo io.ReadWriter
		read filterReader
		write filterWriter
	}
	UnsupportError string
)
func (crw *cipherReadWriter)Read(b []byte)(int,error){
	return crw.read(b,crw.baseIo)
}
func (crw *cipherReadWriter)Write(b []byte)(int,error){
	return crw.write(b,crw.baseIo)
}
func (name UnsupportError) Error() string{
	return "Unsupport method: " + string(name)
}
// encMethod encrypt method

// password Password

// encIo should be object implement io.ReadWriter

// makeio can specified to shadowsock.EncryptIo, shadowsock.ServerEncryptIo, shadowsock.LocalEncryptIo
func NewReadWriter(encMethod string,
	password []byte,
	encIo io.ReadWriter,
	makeio func(*Cipher)(filterReader,filterWriter)) (io.ReadWriter,error){
	var retIo cipherReadWriter
	cinfo,ok := encryptMethod[encMethod]
	if !ok {
		return nil,UnsupportError(encMethod)
	}
	rawKey := GenKey(password,cinfo.keyLen)

	cip,err:=cinfo.newCipher(cinfo.ivLen,rawKey)
	if err != nil {
		return nil,err
	}
	retIo.read,retIo.write = makeio(cip)
	retIo.baseIo=encIo
	return &retIo,nil
}
func EncryptIo(cip *Cipher)(filterReader,filterWriter){
	return decReader(cip),encWriter(cip)
}
func ServerEncryptIoOta(cip *Cipher)(filterReader,filterWriter){
	return decReaderOta(cip),encWriter(cip)
}
func LocalEncryptIoOta(cip *Cipher)(filterReader,filterWriter){
	return decReader(cip),encWriterOta(cip)
}
func decReader   (cip *Cipher) filterReader{
	var reader cipher.StreamReader
	return func(b []byte,r io.Reader)(int,error){
		if reader.S == nil {
			iv:=make([]byte,cip.ivLen)
			_,err := r.Read(iv)
			if err != nil {
				return 0,err
			}
			reader.S,err = cip.dec(iv)
			if err != nil {
				return 0,err
			}
			reader.R=r
		}
		return reader.Read(b)
	}
}
func decReaderOta(cip *Cipher) filterReader{
	panic("not implement")
}
func encWriter   (cip *Cipher) filterWriter{
	var writer cipher.StreamWriter
	return func(b []byte,w io.Writer)(int,error){
		if writer.S == nil {
			iv := make([]byte,cip.ivLen)
			_,err := rand.Read(iv)
			if err != nil {
				return 0,err
			}
			_,err=w.Write(iv)
			if err != nil {
				return 0,err
			}
			writer.S,err = cip.enc(iv)
			if err != nil {
				return 0,err
			}
			writer.W=w
		}
		return writer.Write(b)
	}
}

func encWriterOta(cip *Cipher) filterWriter{
	panic("not implement")
}

//////////////////////////////////////////////////////////////////////////////////////

func GenKey(rawKey []byte,size int) []byte{
	h := md5.New()
	const md5len = 16
	md5sum := func(in []byte) []byte{
		h.Reset()
		h.Write(in)
		return h.Sum(nil)
	}
	blkcnt := (size-1) / md5len + 1
	key := make([]byte,blkcnt * md5len)
	nextkey := make([]byte,md5len+len(rawKey))
	copy(key[:md5len],md5sum(rawKey))
	
	copy(nextkey[md5len:],rawKey)
	for i:=1;i<blkcnt;i++ {
		pos := (i-1) * md5len
		copy(nextkey,key[pos:pos+md5len])
		copy(key[pos+md5len:],md5sum(nextkey))
	}
	return key[:size]
}

