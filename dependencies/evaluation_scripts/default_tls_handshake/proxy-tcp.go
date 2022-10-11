package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

func proxyConnection(c1 net.Conn) (err error) {

	// serverAddr := ":8443"
	serverAddr := ":44301"

	connectTimeout := time.Duration(1000) * time.Millisecond

	// dial the backend
	c2, err := net.DialTimeout("tcp", serverAddr, connectTimeout)
	if err != nil {
		log.Fatal("Failed to dial backend connection", serverAddr, "and err=", err)
		c1.Close()
		return
	}
	log.Printf("Initiated new connection from client: %v, to backend: %v", c2.LocalAddr(), c2.RemoteAddr())

	// join the connections
	var wg sync.WaitGroup
	halfJoin := func(dst net.Conn, src net.Conn) {
		defer wg.Done()

		size := 32 * 1024
		buf := make([]byte, size)

		for {
			nr, er := src.Read(buf)
			fmt.Printf("record: "+hex.EncodeToString(buf[:nr])+" from %s to %s\n", src.RemoteAddr(), dst.RemoteAddr())
			_, ew := dst.Write(buf[0:nr])
			if ew != nil {
				err = ew
				break
			}
			if er != nil {
				if er != io.EOF {
					err = er
				}
				break
			}
		}
	}

	log.Printf("Joining connections: %v %v", c1.RemoteAddr(), c2.RemoteAddr())
	wg.Add(2)
	go halfJoin(c1, c2)
	go halfJoin(c2, c1)
	wg.Wait()
	defer c2.Close()
	defer c1.Close()

	return
}

func main() {

	// run proxy
	proxyAddr := ":9443"
	l, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatal("tcp listen failed, err=", err)
	}

	log.Println("Serving connections on", l.Addr())

	for {
		// accept next connection to this frontend
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Failed to accept new connection for", conn.RemoteAddr())
		}
		log.Printf("Accepted new connection from %v", conn.RemoteAddr())

		// proxy the connection to an backend
		go proxyConnection(conn)
	}
}
