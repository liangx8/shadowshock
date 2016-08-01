package shadowshock

import (
	"fmt"
	"io"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
)


type (
	CipherStreamMaker struct{
		EncryptStream,DecryptStream func([]byte)(cipher.Stream,error)
	}
	Cipher struct{
		streamMaker               CipherStreamMaker
		ota                       bool
		otaRequest                func([]byte,[]byte) []byte
	}
	// read action is not run immdiatary at begin of  connection established
	// so IV only can be retrived at first read invoking.
	agentReader struct{
		read func([]byte) (int,error)
	}
	otaWriter struct{
		chunkIdSumThanWrite func([]byte) (int,error)
	}

	cipherReadWriter struct{
		io.Reader
		io.Writer
	}
	// io Agent, 
	buildDial func(c *Cipher,ivLen int,org io.ReadWriter) dial
	dial func(rawAddr []byte) (io.ReadWriter,error)
)
func (ar *agentReader)Read(b []byte)(int,error){
	return ar.read(b)
}
func (w *otaWriter)Write(b []byte)(int,error){
	return w.chunkIdSumThanWrite(b)
}
// server side

func Service(method,plainKey string,org io.ReadWriter)(io.ReadWriter,[]byte,error){
	var crw cipherReadWriter
	var iv []byte
	rawAddr := make([]byte,1+1+255+2+10)

	var chunkId uint32
	chunkId=0
	cinfo,ok := encryptMethod[method]
	if !ok {
		return nil,nil,ErrUnsupportMethod(method)
	}
	rawKey :=GenKey([]byte(plainKey),cinfo.keyLen)
	cip,err := cinfo.newCipher(rawKey)
	cip.otaRequest = otaReqHead(rawKey)
	if err != nil {	return nil,nil,err}
	crw.Writer,err = encWriter(cip,cinfo.ivLen,org)
	if err != nil {	return nil,nil,err}
	// read initial vector
	var csr cipher.StreamReader
	csr.R=org
	iv = make([]byte,cinfo.ivLen)
	_,err = org.Read(iv)
	if err != nil { return nil,nil,err }
	
	stream,err:=cip.streamMaker.DecryptStream(iv)
	if err != nil { return nil,nil,err }
	csr.S=stream
	_,err = csr.Read(rawAddr[:2])
	if err != nil {
		return nil,nil,fmt.Errorf("Read ATYP and address len bytes incorrected!")
	}
	var headerLen int
	if rawAddr[0] & otaMask == otaMask {

		headerLen=1 + 1 + int(rawAddr[1])+2+10 // ATYP+addrLen+addr+port+hmac_sha1
		_,err = csr.Read(rawAddr[2:headerLen])
		if err != nil { return nil,nil,err}
		chunkSum:=cip.otaRequest(iv,rawAddr[:(headerLen-10)])
		if !cmpChunkSum(chunkSum,rawAddr[headerLen-10:headerLen]){
			return nil,nil,fmt.Errorf("Ota request sum is not match")
		}
		headerLen=headerLen-10
		crw.Reader=&agentReader{
			read:func(b []byte)(int,error){
				// chunk sum and read csr
				_ = chunkId
				chunkId ++
				return 0,fmt.Errorf("not implement")
			},
		}
	} else {
		headerLen=1 + 1 + int(rawAddr[1])+2 // ATYP+addrLen+addr+port
		_,err = csr.Read(rawAddr[2:headerLen])
		if err != nil { return nil,nil,err}
		crw.Reader=&csr
	}
	return &crw,rawAddr[:headerLen],nil
}
// local side
func NewDial(method,plainKey string,org io.ReadWriter,ota bool) (dial,error){
	cinfo,ok := encryptMethod[method]
	if !ok {
		return nil,ErrUnsupportMethod(method)
	}
	rawKey :=GenKey([]byte(plainKey),cinfo.keyLen)
	cip,err := cinfo.newCipher(rawKey)
	if err != nil {
		return nil,err
	}
	cip.ota=ota
	if !ota {
		return dialRegular(cip,cinfo.ivLen,org),nil
	}
	cip.otaRequest = otaReqHead(rawKey)
	return dialOta(cip,cinfo.ivLen,org),nil

}

func dialRegular(cip *Cipher,ivLen int,rw io.ReadWriter)dial{
	var err error
	var crw cipherReadWriter
	return func(rawAddr []byte)(io.ReadWriter,error){
		crw.Reader=decReader(cip,ivLen,rw)
		crw.Writer,err = encWriter(cip,ivLen,rw)
		if err != nil {
			return nil, err
		}
		_,err = crw.Write(rawAddr)
		if err != nil {
			return nil,err
		}
		return &crw,nil
	}
}

func dialOta(cip *Cipher,ivLen int,rw io.ReadWriter) dial {
	var crw cipherReadWriter
	iv :=make([]byte,ivLen)
	var chunkId uint32
	chunkId=0
	return func(rawAddr []byte)(io.ReadWriter,error){
		var err error
		crw.Reader=decReader(cip,ivLen,rw)
		_,err = rand.Read(iv)
		if err != nil { return nil,err }
		_, err = rw.Write(iv)
		if err != nil { return nil,err }
		encStream,err:=cip.streamMaker.EncryptStream(iv)
		if err != nil { return nil,err }
		csw:=&cipher.StreamWriter{S:encStream,W:rw}
		rawAddr[0]= rawAddr[0] | otaMask
		// 发 OTA request
		otaCode:=cip.otaRequest(iv,rawAddr)
		_,err=csw.Write(append(rawAddr,otaCode...))
		if err != nil { return nil,err }

		crw.Writer = &otaWriter{
			chunkIdSumThanWrite:func(b []byte)(int,error){

				chunkBuf:=otaChunkEnc(iv,chunkId,rawAddr)
				_,err:=csw.Write(chunkBuf)
				if err != nil{ return 0,err	}
				chunkId ++
				return csw.Write(b)
			},
		}
	
		return &crw,nil
	}
}
func encWriter(cip *Cipher,ivLen int,w io.Writer) (io.Writer,error){
	iv := make([]byte,ivLen)
	_,err := rand.Read(iv)
	if err != nil { return nil,err }
	_, err = w.Write(iv)
	if err != nil { return nil,err }
	encStream,err:=cip.streamMaker.EncryptStream(iv)
	if err != nil {	return nil,err }
	return &cipher.StreamWriter{S:encStream,W:w},nil
}
func decReader(cip *Cipher,ivLen int,r io.Reader) io.Reader{
	var csr cipher.StreamReader
	csr.R=r
	return &agentReader{
		read:func(b []byte) (int,error){
			if csr.S == nil {
				iv:=make([]byte,ivLen)
				_,err:=csr.Read(iv)
				if err != nil {
					return 0,err
				}
				csr.S,err=cip.streamMaker.DecryptStream(iv)
				if err != nil { return 0,err }

			}
			return csr.Read(b)
		},
	}
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

const (
	otaMask = 0x10
)
