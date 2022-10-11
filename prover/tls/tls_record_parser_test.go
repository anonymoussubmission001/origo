package tls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"testing"
)

func TestProverParser(t *testing.T) {
	const testFolder = "./test_records/"
	parser := new(Parser)
	parser.offset = 0
	parser.handshakeComplete = false
	parser.vers = VersionTLS13

	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	clientPath := testFolder + "ProverSentRecords.raw"

	jsonFile, _ := os.Open(testFolder + jsonFileWrapper(fileName.policyExtractJson))
	jsonByte, _ := ioutil.ReadAll(jsonFile)
	defer jsonFile.Close()
	var pe PolicyExtract
	json.Unmarshal(jsonByte, &pe)
	clientHandshakeSecret, _ := hex.DecodeString(pe.ClientHandshakeTrafficSecret)
	//clientHandshakeSecret, err := parser.readDerivedSecret(clientHandshakeSecretPath)
	//clientTrafficSecret, err := parser.readDerivedSecret(clientTrafficSecretPath)
	//if err != nil {
	//	log.Fatalf("load secret failed: %s\n", err)
	//}
	err := parser.readTransmissionBitstream(clientPath)
	if err != nil {
		log.Fatalln("load transmision data failed")
	} else {
		msg, err := parser.parseHello(clientPath)
		clientHello, ok := msg.(*clientHelloMsg)
		if !ok {
			log.Fatalln("client hello message error")
			return
		}
		fmt.Printf("client hello record(without header): %x\n", clientHello.raw)

		parser.deriveKeyAndIV(cipher, clientHandshakeSecret)
		msg, err = parser.parseFinishedMsg(clientPath)
		if err != nil {
			return
		}
		finished, ok := msg.(*finishedMsg)
		if !ok {
			log.Fatalln("finished error")
		}
		fmt.Printf("decrypted client finished message: %x\n", finished.verifyData)
		clientTrafficSecret, _ := hex.DecodeString(pe.ClientAppTrafficSecret)
		parser.deriveKeyAndIV(cipher, clientTrafficSecret)
		_ = parser.parseApplicationData(clientPath)

		httpRequestContent, err := io.ReadAll(&parser.input)
		fmt.Println("decrypted http request\n" + string(httpRequestContent))
	}
}

func TestSeverParser(t *testing.T) {
	const testFolder = "./test_records/"
	serverSentRecordsparser, clientSentRecordsParser := ParserFactory("./certs", "./test_records")

	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	jsonFile, _ := os.Open(testFolder + jsonFileWrapper(fileName.policyExtractJson))
	jsonByte, _ := ioutil.ReadAll(jsonFile)
	defer jsonFile.Close()
	var pe PolicyExtract
	json.Unmarshal(jsonByte, &pe)

	serverHandshakeTrafficKey, _ := hex.DecodeString(pe.ServerHandshakeTrafficKey)
	serverHandshakeTrafficIV, _ := hex.DecodeString(pe.ServerHandshakeTrafficIV)
	serverTrafficSecret, _ := hex.DecodeString(pe.ServerAppTrafficSecret)
	serverPath := "./test_records/ServerSentRecords.raw"
	clientPath := "./test_records/ProverSentRecords.raw"

	err := serverSentRecordsparser.readTransmissionBitstream(serverPath)
	if err != nil {
		log.Fatalln("load transmision data failed")
	} else {
		err = clientSentRecordsParser.readTransmissionBitstream(clientPath)
		msg, err := clientSentRecordsParser.parseHello(clientPath)
		clientHello, ok := msg.(*clientHelloMsg)
		serverSentRecordsparser.transcript = cipher.hash.New()
		serverSentRecordsparser.transcript.Write(clientHello.marshal())

		msg, err = serverSentRecordsparser.parseHello(serverPath)
		serverHello, ok := msg.(*serverHelloMsg)
		if !ok {
			log.Fatalf("client hello message error: %s\n", err)
		}
		serverSentRecordsparser.transcript.Write(serverHello.marshal())

		fmt.Printf("server hello record(without header): %x\n", serverHello.raw)
		//serverSentRecordsparser.deriveKeyAndIV(cipher, serverHandshakeSecret)
		serverSentRecordsparser.setKeyAndIV(cipher, serverHandshakeTrafficKey, serverHandshakeTrafficIV)
		msg, err = serverSentRecordsparser.parseServerEncryptedExtension(serverPath)
		encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
		if !ok {
			log.Fatalf("encryption extension message error: %s\n", err)
		}
		fmt.Printf("decrypted encrypted extensions: %x\n", encryptedExtensions.raw)
		serverSentRecordsparser.transcript.Write(encryptedExtensions.marshal())
		msg, err = serverSentRecordsparser.parseServerCertificate(serverPath)

		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			log.Fatalf("encryption extension message error: %s\n", err)
		}
		fmt.Printf("decrypted cert verify message: %x\n", certVerify.raw)

		msg, err = serverSentRecordsparser.parseFinishedMsg(serverPath)
		finished, ok := msg.(*finishedMsg)
		if !ok {
			log.Fatalln("finished error")
		}
		fmt.Printf("decrypted server finished message: %x\n", finished.verifyData)
		serverSentRecordsparser.deriveKeyAndIV(cipher, serverTrafficSecret)

		policyExtractFile, err := os.Open(testFolder + jsonFileWrapper(fileName.policyExtractJson))
		defer policyExtractFile.Close()
		policyExtractByte, _ := ioutil.ReadAll(policyExtractFile)
		json.Unmarshal(policyExtractByte, &pe)
		seq, _ := strconv.ParseUint(pe.Seq, 16, 32)
		var i int

		for i = 0; i <= int(seq); i++ {
			if serverSentRecordsparser.rawInput.Len() <= 0 {
				break
			}
			serverSentRecordsparser.readNextRecordWithoutDecryption()
			tmp := make([]byte, 2048)
			n, _ := serverSentRecordsparser.input.Read(tmp)

			if int(seq) == i {
				fmt.Println("======record to prove======")
				fmt.Println("cipher app record: ", hex.EncodeToString(tmp[:n]))
				fmt.Println("block to proof:", hex.EncodeToString(tmp[5 : n-16][pe.StartBlockIdx*16:pe.EndBlockIdx*16]))
				fmt.Println("add:", hex.EncodeToString(tmp[0:5]))
				fmt.Println("ciphertext:", hex.EncodeToString(tmp[5:n-16]))
				fmt.Println("tag:", hex.EncodeToString(tmp[n-16:n]))
				break
			}

			fmt.Println("======skiped record======")
			fmt.Println("add:", hex.EncodeToString(tmp[0:5]))
			fmt.Println("ciphertext:", hex.EncodeToString(tmp[5:n-16]))
			fmt.Println("tag:", hex.EncodeToString(tmp[n-16:n]))

		}
		fmt.Println("end")
	}
}

func TestRunTLSParser(t *testing.T) {
	const testFolder = "./test_records/"
	jsonFile, _ := os.Open(testFolder + jsonFileWrapper(fileName.policyExtractJson))
	jsonByte, _ := ioutil.ReadAll(jsonFile)
	defer jsonFile.Close()

	var jsonData PolicyExtract
	json.Unmarshal(jsonByte, &jsonData)

	ServerHandshakeTrafficKey, _ := hex.DecodeString(jsonData.ServerHandshakeTrafficKey)
	ServerHandshakeTrafficIV, _ := hex.DecodeString(jsonData.ServerHandshakeTrafficIV)

	p, err := RunTLSParser("./certs", testFolder, ServerHandshakeTrafficKey, ServerHandshakeTrafficIV,
		"ServerSentRecords", "ProverSentRecords")
	if err != nil {
		t.Errorf("%s", err)
	}
	fmt.Println(hex.EncodeToString(p.GetH0()))
	fmt.Println(hex.EncodeToString(p.GetH3()))

}
