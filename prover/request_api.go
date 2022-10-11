package prover

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	lp "github.com/anonymoussubmission001/origo/ledger_policy"
	pcreds "github.com/anonymoussubmission001/origo/prover/credentials"
	mtls "github.com/anonymoussubmission001/origo/prover/tls"
	oohttp "github.com/ooni/oohttp"
)

type mtlsConnAdapter struct {
	*mtls.Conn
}

func (c mtlsConnAdapter) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
	}
}

func (c *mtlsConnAdapter) HandshakeContext(ctx context.Context) error {
	errch := make(chan error, 1)
	go func() {
		errch <- c.Conn.Handshake()
	}()
	select {
	case err := <-errch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func mtlsFactory(conn net.Conn, config *tls.Config) oohttp.TLSConn {
	mConfig := &mtls.Config{
		RootCAs:                     config.RootCAs,
		NextProtos:                  config.NextProtos,
		ServerName:                  config.ServerName,
		InsecureSkipVerify:          config.InsecureSkipVerify,
		DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
		CurvePreferences:            []mtls.CurveID{mtls.CurveP256},
		MinVersion:                  config.MinVersion,
		MaxVersion:                  config.MaxVersion,
		CipherSuites:                config.CipherSuites,
	}
	return &mtlsConnAdapter{mtls.Client(conn, mConfig)}
}

func useProxy(proxyURL *url.URL, config *tls.Config,
	tlsClientFactory func(conn net.Conn, config *tls.Config) oohttp.TLSConn) *http.Client {
	w := &oohttp.StdlibTransport{
		Transport: &oohttp.Transport{
			Proxy:                 oohttp.ProxyURL(proxyURL),
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       900 * time.Second,
			TLSHandshakeTimeout:   90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientFactory:      tlsClientFactory,
			TLSClientConfig:       config,
			DisableCompression:    true,
			//DisableKeepAlives:     true,
		},
	}
	return &http.Client{Transport: w}
}

type ApiClient struct {
	Policy             lp.Policy
	Config             ProverConfig
	Client             *http.Client
	Credential         pcreds.ProverCredential
	PolicyFileName     string
	CredentialFileName string
}

func NewClient(policyFileName, credentialFileName string) (*ApiClient, error) {

	// init empty ApiClient
	ac := new(ApiClient)

	// open policy and deserialize to struct
	policyFile, err := os.Open("ledger_policy/" + policyFileName + ".json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer policyFile.Close()
	byteValue, _ := ioutil.ReadAll(policyFile)
	json.Unmarshal(byteValue, &ac.Policy)

	// open config and deserialize to struct
	configFile, err := os.Open("prover/config.json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer configFile.Close()
	byteValue2, _ := ioutil.ReadAll(configFile)
	json.Unmarshal(byteValue2, &ac.Config)

	// open and deserialize credential to struct
	credsFile, err := os.Open("prover/credentials/" + credentialFileName + ".json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer credsFile.Close()
	byteValue3, _ := ioutil.ReadAll(credsFile)
	json.Unmarshal(byteValue3, &ac.Credential)

	// set inputs to client struct
	ac.PolicyFileName = policyFileName
	ac.CredentialFileName = credentialFileName

	// debug
	// fmt.Println("policy:", ac.Policy)
	// fmt.Println("config:", ac.Config)
	// fmt.Println("credential:", ac.Credential)

	// init http client

	// read out url proxy configs
	proxyUrl := "http://" + ac.Policy.Proxies[0].Host + ":" + ac.Policy.Proxies[0].Port
	proxyURL, _ := url.Parse(proxyUrl)

	// set up cert verification
	cert, err := tls.LoadX509KeyPair(ac.Config.PathProverPem, ac.Config.PathProverKey)
	caCert, err := ioutil.ReadFile(ac.Config.PathCaCrt)
	caCertPool, _ := x509.SystemCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// configure tls suite
	config := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
		Certificates:       []tls.Certificate{cert},
		CurvePreferences:   []tls.CurveID{tls.CurveP256},
		NextProtos:         []string{"http/1.1", "pol:" + ac.Config.PolicyPath + JsonFileWrapper(ac.PolicyFileName), "loc:" + ac.Config.StoragePath, "cred:" + "prover/credentials/" + JsonFileWrapper(ac.CredentialFileName)},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
		},
	}

	// create proxy transport
	var ffun func(conn net.Conn, config *tls.Config) oohttp.TLSConn
	ffun = mtlsFactory

	// create http client with transport tunneling through proxy
	ac.Client = useProxy(proxyURL, config, ffun)

	return ac, nil
}

func (ac *ApiClient) RequestAPI() error {

	// build request
	serverUrl := ac.Policy.APIs[0].Url

	// additional private url parts
	if ac.Credential.UrlPrivateParts != "" {

		// adding (e.g.) order identifier
		serverUrl = serverUrl + ac.Credential.UrlPrivateParts
	}
	// request, err := http.NewRequest(oohttp.MethodGet, c.ServerURL, bytes.NewBuffer([]byte{}))
	request, _ := http.NewRequest(oohttp.MethodGet, serverUrl, nil)

	// other requests are for evaluating different query sizes of 0.5kB, 1kB, and 2kB
	buf05kB := make([]byte, 500)
	buf1kB := make([]byte, 1000)
	buf2kB := make([]byte, 2000)
	request05, _ := http.NewRequest(oohttp.MethodGet, serverUrl, bytes.NewBuffer(buf05kB))
	request1, _ := http.NewRequest(oohttp.MethodGet, serverUrl, bytes.NewBuffer(buf1kB))
	request2, _ := http.NewRequest(oohttp.MethodGet, serverUrl, bytes.NewBuffer(buf2kB))
	// dummy if to print values...
	if false {
		log.Println(request05, request1, request2, request)
	}

	// finish request
	request.Close = true
	request.Header.Set("Content-Type", ac.Policy.APIs[0].ContentType)

	// additional modifications of private values
	if ac.Credential.AccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+ac.Credential.AccessToken)
	}

	// send API request
	response, err := ac.Client.Do(request)
	if err != nil {
		log.Println("ac.Client.Do() error:", err)
		return err
	}
	defer response.Body.Close()

	// read response body
	// _, err = ioutil.ReadAll(response.Body)
	// if err != nil {
	// log.Println("ioutil.ReadAll() error:", err)
	// return err
	// }
	// fmt.Println("response body:", string(body))

	return nil
}

func JsonFileWrapper(file string) string {
	return file + ".json"
}
