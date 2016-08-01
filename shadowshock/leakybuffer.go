package shadowshock

type LeakyBuf struct {
	freeList chan []byte
}
var leakyBuf *LeakyBuf
func init(){
	leakyBuf=&LeakyBuf{freeList:make(chan []byte,400)}
}
func (lb *LeakyBuf)Get() []byte{
	select{
	case b:= <- lb.freeList:
		return b
	default:
		return make([]byte,8192)
	}
}
func (lb *LeakyBuf)Put(b []byte){
	select{
	case lb.freeList<- b:
	}
}

