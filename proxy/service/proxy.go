package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type ProxyConfig struct {
	HostAddr                  string
	HostPort                  string
	StoragePath               string
	ProverSentRecordsFileName string
	ServerSentRecordsFileName string
}

var (
	conf ProxyConfig
)

func main() {

	// check if executed inside proxy folder with go run server.go or via proco cmd toolkit
	_, err := os.Stat("./proxy.go")
	for os.IsNotExist(err) {
		os.Chdir("proxy/service/")
		_, err = os.Stat("./proxy.go")
	}

	// parse proxy configs
	absPath, err := filepath.Abs("./config1.json")
	if err != nil {
		log.Println("filepath.Abs error:", err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		log.Println("os.Open error: ", err)
	}
	decoder := json.NewDecoder(file)
	conf = ProxyConfig{}
	decoder.Decode(&conf)

	// logger setup
	f, err := os.OpenFile("evaluation.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Println("os.OpenFile error:", err)
	}
	defer f.Close()
	// Log as JSON instead of the default ASCII formatter.
	// logrus.SetFormatter(&logrus.JSONFormatter{})
	// Output to stderr instead of stdout, could also be a file.
	logrus.SetOutput(f)
	logrus.Warning("---- START PROXY LOG ----.")

	// http handler to catch incoming requests
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Non-http-connect Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		// tcp connection to destination server/host (e.g. paypal)
		conn, err := net.DialTimeout("tcp", r.Host, time.Second*5)
		if err != nil {
			http.Error(w, fmt.Sprintf("Proxy: Unable to dial %s, error: %s", r.Host, err.Error()), http.StatusServiceUnavailable)
			return
		}
		defer conn.Close()

		// write status 200
		w.WriteHeader(http.StatusOK)

		// log.Printf("Proxy: Dialed server: %s %s", conn.RemoteAddr(), conn.LocalAddr())

		// typecast responsewriter to http.Hijacker struct
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Proxy: Unable to typecast hijacker.", http.StatusInternalServerError)
			return
		}

		// hijack connection to client/prover
		reqConn, wbuf, err := hj.Hijack()
		if err != nil {
			http.Error(w, fmt.Sprintf("Proxy: Unable to hijack connection %s", err), http.StatusInternalServerError)
			return
		}
		defer reqConn.Close()
		defer wbuf.Flush()

		// prepare capturing configurations
		proverPath := conf.StoragePath + conf.ProverSentRecordsFileName
		serverPath := conf.StoragePath + conf.ServerSentRecordsFileName

		// errorgroup to catch and wait for connections to finish
		g := new(errgroup.Group)

		// pipe incoming traffic from client to destination connection
		g.Go(func() error {
			return pipe(reqConn, conn, proverPath)
		})

		// pipe destination server responses to client connection
		g.Go(func() error {
			return pipe(conn, reqConn, serverPath)
		})

		// wait until goroutines finish and print any error
		if err := g.Wait(); err != nil {
			log.Println("Error", err.Error())
		}
		logrus.Warning("---- STOP PROXY LOG ----.")
	})

	// start proxy server
	srvProxy := http.Server{Addr: conf.HostAddr + ":" + conf.HostPort, Handler: h}
	fmt.Println("*** proco ***: proxy listening on:", conf.HostAddr, ":", conf.HostPort)

	log.Fatal(srvProxy.ListenAndServe())

}

func pipe(src net.Conn, dst net.Conn, path string) error {

	// open files to store captured traffic
	var err error
	fileHandleRaw, err := os.OpenFile(path+".raw", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	fileHandleTxt, err := os.OpenFile(path+".txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer fileHandleRaw.Close()
	defer fileHandleTxt.Close()

	// code taken from io.copy golang std lib
	// loop copies all data from connection source to connection destination
	for {
		// init buffer
		tmp := make([]byte, 4068)

		// read data from source connection into buffer slice
		m, err := src.Read(tmp)

		// measure time to copy 4kB
		start := time.Now()

		// handle read error
		if err != nil && err != io.EOF {
			if opErr, ok := err.(*net.OpError); ok {
				if strings.Contains(opErr.Error(), "use of closed network connection") {
					return nil
				}
			}
			log.Printf("error: reading from %s to local buffer\n", src.RemoteAddr())
			return err

			// catch end of file delimiter and close connection
		} else if err == io.EOF {
			dst.Close()
			return nil
		}

		// from here on, handle data. no error and no end of file found
		// write captured data to files
		bufferWrite(tmp[:m], fileHandleRaw, fileHandleTxt)

		// copy data from slice buffer to the destination connection
		m, err = dst.Write(tmp[:m])
		if err != nil && err != io.EOF {
			log.Printf("error: writing from local buffer to %s\n", dst.RemoteAddr())
			return err
		}

		// measure proxy delay
		elapsed := time.Since(start)
		logrus.WithFields(logrus.Fields{
			"time": elapsed,
		}).Info("proxy copy connection data took.")
	}

	return err
}

func bufferWrite(msg []byte, fileHandleRaw *os.File, fileHandleTxt *os.File) {

	// flush bytes to file
	buf := bufio.NewWriter(fileHandleRaw)
	buf.Write(msg)
	err := buf.Flush()
	if err != nil {
		log.Println("buf.Flush() error:", err)
	}

	// flush hex string encoded bytes to file
	buf2 := bufio.NewWriter(fileHandleTxt)
	buf2.WriteString(hex.EncodeToString(msg))
	err = buf2.Flush()
	if err != nil {
		log.Println("buf2.Flush() error:", err)
	}
}
