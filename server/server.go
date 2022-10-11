package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

type LocalServerConfig struct {
	HostAddr      string
	HostPort      string
	PathCaCrt     string
	PathServerPem string
	PathServerKey string
	UrlPath       string
}

var (
	serverConfig LocalServerConfig
)

func main() {

	// check if executed inside server with go run server.go or via proco cmd toolkit
	_, err := os.Stat("./server.go")
	for os.IsNotExist(err) {
		os.Chdir("./server")
		_, err = os.Stat("./server.go")
	}

	// parse local server configs
	absPath, err := filepath.Abs("./config1.json")
	if err != nil {
		log.Println("filepath.Abs error:", err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		log.Println("os.Open error: ", err)
	}
	decoder := json.NewDecoder(file)
	serverConfig = LocalServerConfig{}
	decoder.Decode(&serverConfig)

	// parse certificate configs
	var caPath string
	flag.StringVar(&caPath, "path", serverConfig.PathCaCrt, "CA certificates")
	cert, err := tls.LoadX509KeyPair(serverConfig.PathServerPem, serverConfig.PathServerKey)
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Println("ioutil.ReadFile error:", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// configure TLS suite
	tlsConfig := tls.Config{
		RootCAs:                  caCertPool,
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
		},
		NextProtos:         []string{"http/1.1"},
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	// create http server with TLS config
	server := http.Server{
		Addr:      serverConfig.HostAddr + ":" + serverConfig.HostPort,
		TLSConfig: &tlsConfig,
	}

	// set server handler
	http.HandleFunc(serverConfig.UrlPath, response)

	// server start listening for https connections
	fmt.Println("*** proco ***: local https server listening on:", serverConfig.HostAddr, ":", serverConfig.HostPort, serverConfig.UrlPath)
	err = server.ListenAndServeTLS(serverConfig.PathServerPem, serverConfig.PathServerKey)
	if err != nil {
		log.Println("server.ListenAndServeTLS error:", err)
	}
}

func response(w http.ResponseWriter, r *http.Request) {

	// create logfile
	f, err := os.OpenFile("evaluation.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Println("os.OpenFile error:", err)
	}
	defer f.Close()

	// Log as JSON instead of the default ASCII formatter.
	// logrus.SetFormatter(&logrus.JSONFormatter{})

	// Output to stderr instead of stdout, could also be a file.
	logrus.SetOutput(f)

	// Only log the warning severity or above.
	// logrus.SetLevel(logrus.DebugLevel)

	logrus.Warning("---- START SERVER LOG ----.")

	// measure server response time
	start := time.Now()

	// parse request
	r.ParseForm()

	// set response headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(200)

	// debug statements
	// fmt.Println("method:", r.Method)
	// fmt.Println("path:", r.URL.Path)

	// create response body
	message := map[string]interface{}{
		"pair":          "BTCUSDT",
		"data":          "2022.04.27",
		"time":          "12:00:00",
		"volume":        "321654",
		"price":         "38002.2",
		"all time high": "660000.5",
		"24 high":       "396564.3",
		"personal data": map[string]string{
			"age":    "20",
			"income": "1,300,561 Euro",
		},
	}

	// serialize JSON to bytes
	bytePresentation, err := json.Marshal(message)
	if err != nil {
		log.Println("json.Marshal error:", err)
	}

	// write response
	w.Write(bytePresentation)

	// measure elapsed response time
	elapsed := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"time": elapsed,
	}).Info("local server response time took.")

	// announce log ending
	logrus.Warning("---- END SERVER LOG ----.")

}
