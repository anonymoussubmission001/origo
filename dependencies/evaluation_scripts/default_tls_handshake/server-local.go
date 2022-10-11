package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"github.com/sirupsen/logrus"
)

func main() {

	logrus.Info("https server started")

	var caPath string
	flag.StringVar(&caPath, "path", "../certs/ca.crt", "CA certification path")
	cert, err := tls.LoadX509KeyPair("../certs/server.pem", "../certs/server.key")
	caCert, err := ioutil.ReadFile(caPath)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{
		RootCAs:                  caCertPool,
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
		},
		NextProtos:         []string{"h1"},
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	server := http.Server{
		Addr:      "localhost:44301", // 8443
		TLSConfig: &config,
	}
	http.HandleFunc("/my-btc-usdt-order", response)
	err = server.ListenAndServeTLS("../certs/server.pem", "../certs/server.key")
	if err != nil {
		log.Printf("server: write: %s", err)
	}
}

func response(w http.ResponseWriter, r *http.Request) {

	start := time.Now()

	r.ParseForm()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(200)

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
	bytePresentation, err := json.Marshal(message)
	if err != nil {
		log.Printf("server: write: %s", err)
	}
	w.Write(bytePresentation)

	elapsed := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"time": elapsed,
	}).Info("Time Server TLS1.3 https response")
}

