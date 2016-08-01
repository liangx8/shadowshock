package shadowshock

import (

	"net"
)

type (
	Conn struct{
		net.Conn
		read func([]byte) (int,error)
		write func([]byte) (int,error)
	}
)

func (c *Conn)Read(b []byte)(int,error){
	return c.read(b)
}
func (c *Conn)Write(b []byte)(int,error){
	return c.write(b)
}
