package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/mux"
	// "github.com/golang-jwt/jwt/v4"
	"github.com/anonymoussubmission001/origo/prover/gitcoin_server/spa"
	"github.com/golang-jwt/jwt"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var bigRadix = big.NewInt(58)
var bigZero = big.NewInt(0)

type Input struct {
	PolicyName string `json:"policyname"`
}

type Output struct {
	Signature  string `json:"signature"`
	IssueDate  string `json:"issuedate"`
	ExpireDate string `json:"expiredate"`
}

func callOrigo(w http.ResponseWriter, r *http.Request) {

	log.Println("received input")
	fmt.Println("received input")

	// read body
	var req Input
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("received input:", req)
	os.Chdir("../../")

	// call origo
	commands := [][]string{
		[]string{"proxy-start"},
		[]string{"policy-transpile", req.PolicyName, "GitCoinGen"},
		[]string{"prover-credentials-refresh paypal"},
		[]string{"prover-request", req.PolicyName, "paypal"},
		[]string{"proxy-postprocess", req.PolicyName},
		[]string{"proxy-stop"},
		[]string{"prover-compile", "GitCoinGen", req.PolicyName},
		[]string{"prover-prove", "GitCoinGen"},
		[]string{"proxy-verify"},
	}

	for _, cmd := range commands {

		oscmd := exec.Command("./origo", cmd...)
		err = oscmd.Run()
		if err != nil {
			log.Println("cmd.Run() error:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// log.Println("data", string(data))
		log.Println("command", cmd, "executed")
	}

	// keys taken from: https://github.com/Sphereon-Opensource/rn-vc-js/blob/master/bin/vc-js
	// these keys math the Ed25519VerificationKey2018 of vc bazaar repo...
	privKeyBase58 := "53KBp86VkzDKthrZdQCKv4UaAWd74DWCqgbmYmXuLytgbU7pFghAWs23Tdd9iacMLZtkvwdo5vCvDQ8vj24HdJYv"
	pubKeyBase58 := "AoncetDEamr1hreoMiLocvQvCLEu5i5FuQ232zdqie7g"
	// keyType := "Ed25519VerificationKey2018"
	myKeyBytes := FromBase58(privKeyBase58)
	var privKey ed25519.PrivateKey
	privKey = myKeyBytes

	myPubBytes := FromBase58(pubKeyBase58)
	var pubKey ed25519.PublicKey
	pubKey = myPubBytes

	log.Println(pubKey)
	log.Println(privKey.Public())

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	// add credenial except proof part myJsonString := `{"some":"json"}`
	issueDate := time.Now().Format(time.RFC3339)
	expireDate := time.Now().Format(time.RFC3339)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"type":           []string{"VerifiableCredential"},
		"issuer":         "did:key:z6MkrDnt9ZgQiUSU1mcopWgfTHiG9LxUkKHRj4qJSTBWqhcp",
		"@context":       []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		"issuanceDate":   issueDate,
		"expirationDate": expireDate,
		"credentialSubject": map[string]interface{}{
			"id": "did:pkh:eip155:1:0x254a48471b4b1cd3f0a1bfccda5eba4f3b3aec7a",
			"origo_policy": map[string]interface{}{
				"apis": []map[string]interface{}{
					{
						"url":          "https://api-m.sandbox.paypal.com/v2/checkout/orders/",
						"content-type": "application/json",
						"pattern":      "\"currency_code\":\"USD\",\"value\":\"[0-9]+.[0-9]+\",",
						"creds":        true,
					},
				},
				"constraints": []map[string]interface{}{
					{
						"value":      "098.00",
						"constraint": "GT",
					},
				},
				"proxies": []map[string]interface{}{
					{
						"host":      "localhost",
						"port":      "8082",
						"mode":      "signature",
						"pubKey":    "3282734573475",
						"algorithm": "Ed25519",
					},
				},
			},
		},
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("tokenStrg", tokenString)

	// return message
	res := Output{Signature: tokenString, IssueDate: issueDate, ExpireDate: expireDate}
	json.NewEncoder(w).Encode(res)
}

func main() {

	// init server
	mux := mux.NewRouter()
	mux.HandleFunc("/origo", callOrigo).Methods("POST")
	spa.AttachRoutes(mux, "./frontend/build")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// two functions below copied from: https://github.com/bitmark-inc/bitmarkd/blob/master/util/base58.go
// SPDX-License-Identifier: ISC
// Copyright (c) 2013-2014 Conformal Systems LLC.
// Copyright (c) 2014-2020 Bitmark Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// FromBase58 decodes a modified base58 string to a byte slice.
func FromBase58(b string) []byte {
	answer := big.NewInt(0)
	j := big.NewInt(1)

	for i := len(b) - 1; i >= 0; i-- {
		tmp := strings.IndexAny(alphabet, string(b[i]))
		if tmp == -1 {
			return []byte("")
		}
		idx := big.NewInt(int64(tmp))
		tmp1 := big.NewInt(0)
		tmp1.Mul(j, idx)

		answer.Add(answer, tmp1)
		j.Mul(j, bigRadix)
	}

	tmpval := answer.Bytes()

	var numZeros int
loop:
	for numZeros = 0; numZeros < len(b); numZeros++ {
		if b[numZeros] != alphabet[0] {
			break loop
		}
	}
	flen := numZeros + len(tmpval)
	val := make([]byte, flen)
	copy(val[numZeros:], tmpval)

	return val
}

// ToBase58 encodes a byte slice to a modified base58 string.
func ToBase58(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0, len(b)*136/100)
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		answer = append(answer, alphabet[mod.Int64()])
	}

	// leading zero bytes
loop:
	for _, i := range b {
		if i != 0 {
			break loop
		}
		answer = append(answer, alphabet[0])
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}
