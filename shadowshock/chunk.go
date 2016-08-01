package shadowshock

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)


func hmacSha1(key ,data []byte)[]byte{
	hs := hmac.New(sha1.New,key)
	hs.Write(data)
	return hs.Sum(nil)[:10]
}

func otaReqHead(key []byte) func([]byte,[]byte)[]byte{
	return func(iv,data []byte)[]byte{
		return hmacSha1(append(iv,key...),data)
	}
}
func otaChunkEnc(iv []byte,chunkId uint32,data []byte)[]byte{
	dataLen := make([]byte,2)
	binary.BigEndian.PutUint16(dataLen,uint16(len(data)))
	chunkBuf :=make([]byte,4)
	binary.BigEndian.PutUint32(chunkBuf,chunkId)
	return append(dataLen,hmacSha1(append(iv,chunkBuf...),data)...)
}

func cmpChunkSum(a,b []byte) bool{
	if len(a) != len(b) {return false}
	for i,_ := range a{
		if a[i]!=b[i] { return false}
	}
	return true
}
