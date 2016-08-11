package main

import (
	"flag"
	"log"
	"os"
	"io/ioutil"
	"io"
	"net"
	"errors"
//	"fmt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	sh "github.com/liangx8/shadowshock/shadowshock"

)
type (
	ServerCipher struct {
		name,server string
		cipher *ss.Cipher
		failCnt int
	}
)
var servers []*ServerCipher

var debug ss.DebugLog

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

func handShake(conn net.Conn) error {
	buf := make([]byte,258)
	ss.SetReadTimeout(conn)
	n,err := io.ReadAtLeast(conn,buf,2) //
	if  err != nil {
		return err
	}
	if buf[0] != 5 {
		return errVer
	}
	nmethod := int(buf[1])
	msgLen := nmethod + 2
	if n != msgLen{
		return errAuthExtraData
	}
	_,err = conn.Write([]byte{5,0})
	return err
}
func getRequest(conn net.Conn) (rawAddr []byte, host string, err error){
	buf := make([]byte,263)
	var n int
	ss.SetReadTimeout(conn)
	n, err = io.ReadAtLeast(conn,buf,5)
	if err != nil {
		return
	}
	if buf[0] != 5 {
		err = errVer
		return
	}
	if buf[1] != 1 {
		err = errCmd
		return
	}
	reqLen := -1
	switch buf[3]{
	case 1:// IPv4
		reqLen = 3 + 1 + net.IPv4len + 2
		host = net.IP(buf[4:4+net.IPv4len]).String()
	case 3:// domain address
		reqLen = int(buf[4]) + 3 + 1 + 1 + 2
		host = string(buf[5:5 + buf[4]])
	case 4:// IPv6
		reqLen = 3 + 1 + net.IPv6len + 2
		host = net.IP(buf[4:4+net.IPv6len]).String()
	default:
		err = errAddrType
		return
	}
	if n != reqLen {
		err = errReqExtraData
		return
	}
	rawAddr = buf[3:reqLen]
	return
}
func handleConnection(conn net.Conn){
	defer conn.Close()

	debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	if err := handShake(conn); err != nil {
		debug.Printf("hand shake fail with %v\n",err)
	}
	
	rawAddr,host,err := getRequest(conn)
	if err != nil {
		debug.Printf("Get Request error with %v\n",err)
		return
	} else {
		debug.Printf("connect to %s\n",host)
	}
	_,err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation",err)
		return
	}
	remote,err:=connectToServer(rawAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer func(){
		debug.Printf("close connection of %s\n",host)
		remote.Close()
	}()
	go ss.PipeThenClose(conn,remote)
	ss.PipeThenClose(remote,conn)
	
}
func connectToServer(rawaddr []byte)(remote *ss.Conn,err error){
	// use available server
	for _,s := range servers{
		if s.failCnt > 0 { continue }
		debug.Printf("using server %s(%s)\n",s.name,s.server)
		remote,err = ss.DialWithRawAddr(rawaddr,s.server,s.cipher.Copy())
		if err != nil {
			log.Println("error connecting to shadowsocks server:",err)
			s.failCnt ++
			continue
		}
		s.failCnt = 0
		return
	}
	// retry failure server
	for _,s := range servers{
		debug.Printf("tring server %s(%s)\n",s.name,s.server)
		remote,err = ss.DialWithRawAddr(rawaddr,s.server,s.cipher.Copy())
		if err != nil {
			log.Println("(tring)error connecting to shadowsocks server:",err)
			s.failCnt ++
			continue
		}
		s.failCnt = 0
		return
	}
	return nil,errors.New("Not available server")
}
func run(cfg *sh.Config){
	if cfg.LocalPort == "" {
		cfg.LocalPort = "1080"
		debug.Println("miss local-port option, use default(1080)")
	}
	ltn,err := net.Listen("tcp",":"+cfg.LocalPort)
	if err != nil { log.Fatal(err) }
	log.Printf("Starting local socks5 at :'%s' ...\n",cfg.LocalPort)
	for {
		conn,err := ltn.Accept()
		if err != nil {
			log.Println("Accept:",err)
			continue
		}
		go handleConnection(conn)
	}
}
func serverList(cfg *sh.Config){
	hasPort := func(s string) bool {
		_, port, err := net.SplitHostPort(s)
		if err != nil { return false }
		return port != ""
	}
	n := len(cfg.Servers)
	servers = make([]*ServerCipher,n)
	cipherCache := make(map[string]*ss.Cipher)
	i := 0
	for _,si := range cfg.Servers {
		if !hasPort(si.Server) {
			log.Fatalf("no port for server",si.Server)
		}
		cacheKey := si.Method + "|" + si.Password
		cip,ok := cipherCache[cacheKey]
		if !ok {
			var err error
			cip, err = ss.NewCipher(si.Method,si.Password)
			if err != nil {
				log.Fatal("Failed generating cipher:",err)
			}
			cipherCache[cacheKey]=cip
		}
		servers[i] = &ServerCipher{name:si.Name,server:si.Server,cipher:cip,failCnt:0}
		i++
	}
	servers = servers[:i]
	if debug {
		for _,s := range servers {
			debug.Printf("Available server:%s(%s)\n",s.name,s.server)
		}
	}
	
}
func main(){
	var configFile string
	var cfg sh.Config
	flag.StringVar(&configFile,"c","config.yaml","specify config file")
	flag.BoolVar((*bool)(&debug),"d",false, "print debug message")
	flag.Parse()
	rd,err := os.Open(configFile)

	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()
	buf,err:=ioutil.ReadAll(rd)
	if err != nil {log.Fatal(err)}
	if err := sh.ParseConfig(buf,&cfg); err != nil {
		log.Println(err)
	}
	serverList(&cfg)
	run(&cfg)
}
