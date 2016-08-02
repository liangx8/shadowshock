package main

import (
	"flag"
	"log"
	"os"
	"io/ioutil"
	"net"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	yaml "gopkg.in/yaml.v2"
)

type (
	ServerInfo struct{
		Server,Name,Method,Password string
		Ota bool
	}
	Config struct{
		Timeout int
		LocalPort string `yaml:"local_port"`
		Servers []ServerInfo
	}
)
var debug ss.DebugLog
func parseConfig(cfg *Config){
	if cfg.LocalPort == "" {
		debug.Println("use local port 1080")
		cfg.LocalPort="1080"
	}
	for _,s := range cfg.Servers{
		if s.Server == "" || s.Method == "" || s.Password == "" {
			log.Fatal("Please provide information include 'server', 'method' and 'password'")
		}
	}
}
func run(cfg *Config){
	ltn,err := net.Listen("tcp",":"+cfg.LocalPort)
	if err != nil { log.Fatal(err) }
	for {
		conn,err := ltn.Accept()
		if err != nil {
			log.Println("Accept:",err)
			continue
		}
		defer conn.Close()
	}
}
func main(){
	var configFile string
	var cfg Config
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
	err = yaml.Unmarshal(buf,&cfg)
	if err != nil {log.Fatal(err)}
	run(&cfg)
}
