package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

func main() {
	var port int
	flag.IntVar(&port, "port", 8082, "The port to listen on")
	flag.Parse()
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Non-http-connect Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		start := time.Now()

		defer r.Body.Close()

		conn, err := net.DialTimeout("tcp", r.Host, time.Second*5)
		if err != nil {
			http.Error(w, fmt.Sprintf("Proxy: Unable to dial %s, error: %s", r.Host, err.Error()), http.StatusServiceUnavailable)
			return
		}
		defer conn.Close()
		w.WriteHeader(http.StatusOK)

		log.Printf("Proxy: Dialed server: %s %s", conn.RemoteAddr(), conn.LocalAddr())

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Proxy: Unable to hijack connection", http.StatusInternalServerError)
			return
		}

		reqConn, wbuf, err := hj.Hijack()
		if err != nil {
			http.Error(w, fmt.Sprintf("Proxy: Unable to hijack connection %s", err), http.StatusInternalServerError)
			return
		}
		defer reqConn.Close()
		defer wbuf.Flush()

		g := new(errgroup.Group)
		g.Go(func() error {
			return pipe(reqConn, conn)
		})
		g.Go(func() error {
			return pipe(conn, reqConn)
		})

		if err := g.Wait(); err != nil {
			log.Println("Error", err.Error())
		}

		elapsed := time.Since(start)
		log.Printf("time elapsed for connection:", elapsed)
		log.Printf("Proxy: Connection %s done.", conn.RemoteAddr())
	})))
}

func pipe(src net.Conn, dst net.Conn) error {
	var err error
	for {
		tmp := make([]byte, 4068)
		m, err := src.Read(tmp)
		if err != nil && err != io.EOF {
			if opErr, ok := err.(*net.OpError); ok {
				if strings.Contains(opErr.Error(), "use of closed network connection") {
					return nil
				}
			}
			log.Printf("error: reading from %s to local buffer\n", src.RemoteAddr())
			return err

		} else if err == io.EOF {
			dst.Close()
			return nil
		}

		m, err = dst.Write(tmp[:m])
		if err != nil && err != io.EOF {
			log.Printf("error: writing from local buffer to %s\n", dst.RemoteAddr())
			return err
		}
		log.Printf("record: "+hex.EncodeToString(tmp[:m])+" from %s to %s\n", src.RemoteAddr(), dst.RemoteAddr())
	}

	return err
}

