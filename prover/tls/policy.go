package tls

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"regexp"
	"strings"

	lp "github.com/anonymoussubmission001/origo/ledger_policy"
	pcreds "github.com/anonymoussubmission001/origo/prover/credentials"
)

const (
	// floatType     = "float"
	contentType   = "application/json"
	greaterThan   = "GT"
	lessThan      = "LT"
	equalThan     = "EQ"
	signatureMode = "signature"
)

const (
	defaultOption uint8 = 1
)

const (
	floatingNumPattern1 string = "\"[0-9]+.[0-9]+\""
)

type policyJson struct {
	Identifier       int       `json:"identifier"`
	Mode             string    `json:"mode"`
	Constraint       string    `json:"constraint"`
	Type             string    `json:"type"`
	Threshold        string    `json:"threshold"`
	CompareMaxBitLen int       `json:"compareMaxBitLen"`
	Endpoints        string    `json:"endpoint"`
	Host             string    `json:"host"`
	Key              string    `json:"key"`
	Pattern          string    `json:"pattern"`
	proxySpec        proxySpec `json:"proxySpec"`
}

type proxySpec struct {
	pubKey    string `json:"pubKey"`
	Algorithm string `json:"algorithm"`
}

type policy interface {
	locateResponseKeyValuePatternPosition([]byte) bool
	locateQueryPatternPosition(plaintext []byte) bool
	//extractSubstring() bool
	saveContext() bool
	revertSeq([]byte)
	prepareAESGCMAuthProof(aesKey []byte, iv []byte, plaintext []byte)
	applyPolicy(key []byte, iv []byte, seq []byte, data []byte, storage savedData, storageLoc string) bool
}

type exchangePolicy struct {
	keyValuePairReg *regexp.Regexp
	valueReg        *regexp.Regexp
	entrypointReg   *regexp.Regexp
	hostReg         *regexp.Regexp

	appRecordCount       int
	startIdxKeyValuePair int
	endIdxKeyValuePair   int
	startIdxValue        int
	endIdxValue          int
	startBlockIdx        int
	endBlockIdx          int
	keyValueStartPattern string
	DotPosition          int

	keyValuePair []byte

	threshold float64
	seq       []byte
	hasFound  bool
	storage   savedData

	Threshold        string
	CompareMaxBitLen int
}

func (ep *exchangePolicy) locateResponseKeyValuePatternPosition(plaintext []byte) bool {

	keyValuePair := ep.keyValuePairReg.FindString(string(plaintext))
	if len(keyValuePair) != 0 {
		idxKeyValuePair := ep.keyValuePairReg.FindStringIndex(string(plaintext))
		idxValue := ep.valueReg.FindStringIndex(keyValuePair)
		ep.hasFound = true
		ep.startIdxKeyValuePair = idxKeyValuePair[0]
		ep.endIdxKeyValuePair = idxKeyValuePair[1]
		ep.startIdxValue = idxValue[0]
		ep.endIdxValue = idxValue[1]

		ep.startBlockIdx = idxKeyValuePair[0] / 16
		if idxKeyValuePair[1]%16 != 0 {
			ep.endBlockIdx = idxKeyValuePair[1]/16 + 1
		} else {
			ep.endBlockIdx = idxKeyValuePair[1] / 16
		}
		ep.keyValuePair = plaintext[ep.startIdxKeyValuePair:ep.endIdxKeyValuePair]
		ep.keyValueStartPattern = string(plaintext[ep.startIdxKeyValuePair : ep.startIdxKeyValuePair+ep.startIdxValue+1])
		ep.DotPosition = bytes.Index(plaintext[ep.startIdxKeyValuePair:ep.endIdxKeyValuePair][ep.startIdxValue+1:ep.endIdxValue-1], []byte("."))

		return true
	}
	return false
}

func (ep *exchangePolicy) locateQueryPatternPosition(plaintext []byte) bool {
	hostIdx := ep.hostReg.FindStringIndex(string(plaintext))
	entrypointIdx := ep.entrypointReg.FindStringIndex(string(plaintext))
	if hostIdx != nil || entrypointIdx != nil {
		return true
	}
	return false
}

func (ep *exchangePolicy) prepareAESGCMAuthProof(aesKey []byte, iv []byte, plaintext []byte) {
	aes, _ := NewAES(aesKey)
	H := make([]byte, 16)
	aes.encryptBlock(H, aes.roundKeys)
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i, b := range ep.seq {
		nonce[4+i] ^= b
	}
	nonceMask := append(nonce, []byte{0x00, 0x00, 0x00, 0x01}...)

	aes.encryptBlock(nonceMask, aes.roundKeys)

	ep.storage.plaintextToProof = plaintext[ep.startBlockIdx*16 : ep.endBlockIdx*16]
	ep.storage.galoisKeyCipher = H
	ep.storage.taskMaskCipher = nonceMask

	ciphertext := make([]byte, (ep.endBlockIdx-ep.startBlockIdx)*16)
	copy(ciphertext, ep.storage.record[ep.startBlockIdx*16+recordHeaderLen:ep.endBlockIdx*16+recordHeaderLen])

	ep.storage.CiphertextToProof = ciphertext
}

func (ep *exchangePolicy) applyPolicy(key []byte, iv []byte, seq []byte, data []byte, storage savedData, storageLoc string) bool {
	// try finding substring match of key value pattern in data chunks
	hasFoundLocation := ep.locateResponseKeyValuePatternPosition(data)
	ep.storage = storage
	if hasFoundLocation {
		ep.revertSeq(seq)
		ep.prepareAESGCMAuthProof(key, iv, data)
		err := ep.savePolicyExtractJson(fileName.policyExtractJson, storageLoc)
		if err != nil {
			return false
		}
	}
	return hasFoundLocation
}

//func (ep *exchangePolicy) extractSubstring() bool {
//	return true
//}

func (ep *exchangePolicy) saveContext() bool {
	return true
}

func (ep *exchangePolicy) revertSeq(seq []byte) {
	if ep.seq == nil {
		ep.seq = make([]byte, 8)
	}
	copy(ep.seq, seq)
	ep.seq[7] = seq[7] - 1
}

func policyJsonParser(path string) (lp.Policy, error) {
	policyByteFormat, err := ioutil.ReadFile(path)
	// var pJson policyJson
	var pJson lp.Policy
	err = json.Unmarshal(policyByteFormat, &pJson)
	return pJson, err
}

func credsJsonParser(path string) (pcreds.ProverCredential, error) {
	// static path
	policyByteFormat, err := ioutil.ReadFile(path)
	// var pJson policyJson
	var pJson pcreds.ProverCredential
	err = json.Unmarshal(policyByteFormat, &pJson)
	return pJson, err
}

func policyFactory(path string, credsPath string) (policy, error) {

	pJson, err := policyJsonParser(path)
	if err != nil {
		return nil, errors.New("can not parse policy json")
	}

	cJson, err := credsJsonParser(credsPath)
	if err != nil {
		return nil, errors.New("can not parse credentials json")
	}

	// parse policy
	api := pJson.APIs[0]
	creds := api.Creds
	constraint := pJson.Constraints[0]
	proxy := pJson.Proxies[0]

	// check policy mode and content type
	if proxy.Mode == signatureMode && api.ContentType == contentType {

		// create exchangePolicy and set values
		p := new(exchangePolicy)
		p.keyValuePairReg, err = regexp.Compile(api.Pattern)

		// get host value from URL
		fullUrl := api.Url
		if creds {
			// load private credential and append privateURLPart
			fullUrl += cJson.UrlPrivateParts
		}
		host, endpoint := extractDomainEndpoint(fullUrl)

		p.hostReg, err = regexp.Compile("Host: " + host)
		p.entrypointReg, err = regexp.Compile(endpoint)

		// constraint Value
		if constraint.Constraint == greaterThan || constraint.Constraint == lessThan {
			newValue := strings.Split(constraint.Value, ".")
			constraint.Value = newValue[0] + newValue[1]
		}
		// in case of equalThan, keep Value as it is because a stringmatch will be performed

		p.Threshold = constraint.Value
		// p.CompareMaxBitLen = pJson.CompareMaxBitLen

		// setting comparemaxBitLen to 126 as done by gadget.math.Mod in libsnark
		p.CompareMaxBitLen = 126
		if err != nil {
			log.Println("invalid regex pattern")
			return nil, errors.New("invalid regex pattern")
		}

		// valueReg wont be used in equalThan because the circuit does not use the value
		p.valueReg, err = regexp.Compile(floatingNumPattern1)
		if err != nil {
			log.Println("invalid regex pattern")
			return nil, errors.New("invalid regex pattern")
		}
		return p, nil
	}
	return nil, errors.New("unsupported policy")

}

func extractDomainEndpoint(url string) (host string, endpoint string) {

	// regex and string splitting
	urlReduced := strings.Split(url, "://")[1]
	match, err := regexp.MatchString(":[0-9]+/", urlReduced)
	if err != nil {
		log.Println("regexp.MatchString() error:", err)
	}
	if match {
		// port is specified in url
		urlReduced2 := strings.Split(urlReduced, ":")
		host = urlReduced2[0]
		endpoint = strings.Split(urlReduced2[1], "/")[1]
	} else {
		// port not specified
		urlReduced2 := strings.Split(urlReduced, "/")
		host = urlReduced2[0]
		endpoint = strings.Join(urlReduced2[1:], "/")
	}

	return
}
