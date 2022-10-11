package tls

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type Parser struct {
	offset              int64
	handshakeComplete   bool
	rawInput            bytes.Buffer
	hand                bytes.Buffer
	input               bytes.Reader
	clientHello         *clientHelloMsg
	serverHello         *serverHelloMsg
	encryptedExtensions *encryptedExtensionsMsg
	certMsg             *certificateMsgTLS13
	certVerify          *certificateVerifyMsg
	finished            *finishedMsg
	vers                int
	seq                 [8]byte
	handshakeKey        []byte
	handshakeIV         []byte
	cipher              any
	transcript          hash.Hash
	verifiedChains      [][]*x509.Certificate
	peerCertificates    []*x509.Certificate
	certPool            *x509.CertPool
	path                string
}

func (p *Parser) readDerivedSecret(path string) (secret []byte, err error) {
	fd, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatalf("tls parser:%s\n", err)
	}
	defer fd.Close()

	fileReader := bufio.NewReader(fd)
	secret = make([]byte, 32)
	n, err := fileReader.Read(secret)
	if n != 32 && err != nil {
		return nil, errors.New("secret")
	}
	return secret, nil
}

func (p *Parser) readDerivedSecretByLength(path string, length uint8) (secret []byte, err error) {
	fd, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatalf("tls parser:%s\n", err)
	}
	defer fd.Close()

	fileReader := bufio.NewReader(fd)
	secret = make([]byte, length)
	n, err := fileReader.Read(secret)
	if n != 32 && err != nil {
		return nil, errors.New("key/iv")
	}
	return secret, nil
}

func (p *Parser) readTransmissionBitstream(path string) (err error) {
	fd, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	defer fd.Close()
	if err != nil {
		log.Fatalf("tls parser:%s\n", err)
		return err
	}
	fileReader := bufio.NewReader(fd)
	fileInfo, err := fd.Stat()
	if err != nil {
		return err
	}
	fileSize := int(fileInfo.Size())
	//fmt.Println(fileSize)
	if err := p.readCompleteBitstream(fileReader, fileSize); err != nil {
		if err == io.ErrUnexpectedEOF && p.rawInput.Len() == 0 {
			err = io.EOF
		}
		return err
	}
	return nil
}

func (p *Parser) deriveKeyAndIV(suite *cipherSuiteTLS13, secret []byte) (key []byte, iv []byte) {
	key, iv = suite.trafficKey(secret)
	p.cipher = suite.aead(key, iv)
	for i := range p.seq {
		p.seq[i] = 0
	}
	return key, iv
}

func (p *Parser) setKeyAndIV(suite *cipherSuiteTLS13, key []byte, iv []byte) {
	p.cipher = suite.aead(key, iv)
	for i := range p.seq {
		p.seq[i] = 0
	}
}

func (p *Parser) resetSeq() {
	for i := range p.seq {
		p.seq[i] = 0
	}
}

func (p *Parser) readRecord(path string) error {

	if p.rawInput.Len() <= 0 {
		log.Println("finish parsing")
		return nil
	}
	handshakeComplete := p.handshakeComplete

	p.input.Reset(nil)

	hdr := p.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		log.Fatalf("tls parser: unsupported SSLv2 handshake received\n")
		return alertProtocolVersion
	}

	//vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])

	if n > maxCiphertextTLS13 {
		log.Fatalf("tls parser: oversized record received with length %d", n)
		return alertRecordOverflow
	}

	record := p.rawInput.Next(recordHeaderLen + n)
	data, typ, err := p.decrypt(record)
	if err != nil {
		log.Println("tls EEERROR")
		log.Println("tls parser:", err)
		return err
	}
	if len(data) > maxPlaintext {
		log.Println("tls parser: record overflow")
		return alertRecordOverflow
	}

	switch typ {
	default:
		log.Println("tls parser: wrong message type")
		return alertUnexpectedMessage
	case recordTypeAlert:
		log.Println("tls parser: abort parsing due to alert message")
		return alertUnexpectedMessage
	case recordTypeChangeCipherSpec:
		p.handshakeComplete = true
		// log.Println("tls parser: escape change cipher spec")
		return p.readRecord(path)
	case recordTypeApplicationData:

		if len(data) == 0 {
			log.Fatalln("tls parser: application data fails to read")
			return p.readRecord(path)
		}
		// Note that data is owned by p.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because p.rawInput is
		// not read from or written to until p.input is drained.
		p.input.Reset(data)

	case recordTypeHandshake:
		p.hand.Write(data)
	}
	return nil
}

func (p *Parser) readNextRecordWithoutDecryption() error {
	if p.rawInput.Len() <= 0 {
		log.Println("no record")
		return nil
	}
	handshakeComplete := p.handshakeComplete

	p.input.Reset(nil)

	hdr := p.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		log.Fatalf("tls parser: unsupported SSLv2 handshake received\n")
		return alertProtocolVersion
	}

	//vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])

	if n > maxCiphertextTLS13 {
		log.Fatalf("tls parser: oversized record received with length %d", n)
		return alertRecordOverflow
	}

	record := p.rawInput.Next(recordHeaderLen + n)
	p.input.Reset(record)
	return nil
}

func (p *Parser) readCompleteBitstream(r io.Reader, fileSize int) error {

	if p.rawInput.Len() == 0 {
		p.rawInput.Grow(fileSize)
		_, err := p.rawInput.ReadFrom(&atLeastReader{r, int64(fileSize)})
		if err != nil {
			return err
		}
		return nil
	}

	return nil
}

func (p *Parser) incSeq() {
	for i := 7; i >= 0; i-- {
		p.seq[i]++
		if p.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

func (p *Parser) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if p.vers == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	explicitNonceLen := 0

	if p.cipher != nil && p.handshakeComplete {

		if len(payload) < explicitNonceLen {
			return nil, 0, alertBadRecordMAC
		}
		nonce := payload[:explicitNonceLen]
		if len(nonce) == 0 {
			nonce = p.seq[:]
		}
		payload = payload[explicitNonceLen:]

		var additionalData []byte

		additionalData = record[:recordHeaderLen]

		var err error
		c := p.cipher.(aead)
		plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
		if err != nil {
			return nil, 0, alertBadRecordMAC
		}

		if p.vers == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	p.incSeq()
	return plaintext, typ, nil
}

func (p *Parser) parseHandshake(path string) (interface{}, error) {
	for p.hand.Len() < 4 {
		if err := p.readRecord(path); err != nil {
			return nil, err
		}
	}

	data := p.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, errors.New("tls: handshake message of length exceeds maximum  bytes")
	}
	for p.hand.Len() < 4+n {
		if err := p.readRecord(path); err != nil {
			return nil, err
		}
	}
	data = p.hand.Next(4 + n)
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		m = new(newSessionTicketMsgTLS13)
	case typeCertificate:
		m = new(certificateMsgTLS13)
	case typeCertificateRequest:
		m = new(certificateRequestMsgTLS13)
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: p.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		return nil, errors.New("tls parser: unexpected handshake type")
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, errors.New("tls parser: unmarshal error")
	}
	return m, nil
}

func (p *Parser) parseHello(path string) (interface{}, error) {
	msg, err := p.parseHandshake(path)
	if err != nil {
		return nil, errors.New("tls parser: server hello error")
	}
	return msg, nil
}

func (p *Parser) parseServerEncryptedExtension(path string) (interface{}, error) {
	msg, err := p.parseHandshake(path)
	if err != nil {
		return nil, errors.New("tls parser: server encrypted extension error")
	}
	return msg, nil
}

func (p *Parser) parseServerCertificate(path string) (interface{}, error) {
	msg, err := p.parseHandshake(path)

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		p.transcript.Write(certReq.marshal())
		msg, err = p.parseHandshake(path)
		if err != nil {
			return nil, err
		}
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	p.certMsg = certMsg
	if !ok {
		return nil, unexpectedMessageError(certMsg, msg)
	}
	p.transcript.Write(certMsg.marshal())
	if len(certMsg.certificate.Certificate) == 0 {
		return nil, errors.New("tls: received empty certificates message")
	}

	if err := p.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return nil, err
	}

	msg, err = p.parseHandshake(path)
	if err != nil {
		return nil, err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		return nil, unexpectedMessageError(certVerify, msg)
	}

	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		return nil, errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return nil, err
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return nil, errors.New("tls: certificate used with invalid signature algorithm")
	}

	signed := signedMessage(sigHash, serverSignatureContext, p.transcript)
	if err := verifyHandshakeSignature(sigType, p.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		return nil, errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	p.transcript.Write(certVerify.marshal())
	return certVerify, nil
}

func (p *Parser) parseFinishedMsg(path string) (interface{}, error) {
	msg, err := p.parseHandshake(path)
	if err != nil {
		return nil, errors.New("tls parser: server encrypted extension error")
	}
	finished, ok := msg.(*finishedMsg)
	if !ok {
		return nil, unexpectedMessageError(finished, msg)
	}
	return msg, nil
}

func (p *Parser) parseApplicationData(path string) error {
	if err := p.readRecord(path); err != nil {
		return err
	}
	return nil
}

func (p *Parser) VerifyGCMTag(seq int, startBlockIdx, endBlockIdx int, tagMaskCipher, galoisKexCipher []byte) (bool, []byte) {

	//policyExtractByte, _ := ioutil.ReadAll(policyExtractFile)
	//var pe policyExtract
	//json.Unmarshal(policyExtractByte, &pe)
	//seq, _ := strconv.ParseUint(pe.Seq, 16, 32)
	var i int
	for i = 0; i <= seq; i++ {
		if p.rawInput.Len() <= 0 {
			break
		}
		p.readNextRecordWithoutDecryption()
		tmp := make([]byte, 2048)
		n, _ := p.input.Read(tmp)

		if seq == i {
			tag := DynAuthGCM(tagMaskCipher, tmp[5:n-16], galoisKexCipher, tmp[0:5])
			if bytes.Compare(tag, tmp[n-16:n]) != 0 {
				fmt.Println("Tag calculation failed.")
			}
			// fmt.Println("tag authen success")

			return true, tmp[:n][startBlockIdx*16+5 : endBlockIdx*16+5]
		}

	}
	// fmt.Println("end")
	return false, nil
}

func RunTLSParser(caPath string, recordPath string, serverHandshakeTrafficKey, serverHandshakeTrafficIV []byte,
	filenameServerSentRecords, filenameProverSentRecords string) (*Parser, error) {
	serverSentRecordsParser, clientSentRecordsParser := ParserFactory(caPath, recordPath)
	serverSentRecordsParser.offset = 0
	serverSentRecordsParser.handshakeComplete = false
	serverSentRecordsParser.vers = VersionTLS13

	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	serverPath := recordPath + filenameServerSentRecords + ".raw"
	clientPath := recordPath + filenameProverSentRecords + ".raw"

	err := serverSentRecordsParser.readTransmissionBitstream(serverPath)
	err = clientSentRecordsParser.readTransmissionBitstream(clientPath)
	if err != nil {
		return nil, errors.New("TLS Parser: can not read records")
	} else {

		msg, err := clientSentRecordsParser.parseHello(clientPath)
		if err != nil {
			return nil, errors.New("TLS Parser: client hello message error")
		}
		clientHello, ok := msg.(*clientHelloMsg)
		serverSentRecordsParser.clientHello = clientHello
		serverSentRecordsParser.transcript = cipher.hash.New()
		serverSentRecordsParser.transcript.Write(clientHello.marshal())
		// fmt.Printf("TLS Parser: client hello record(without header): %x\n", clientHello.raw)
		msg, err = serverSentRecordsParser.parseHello(serverPath)
		serverHello, ok := msg.(*serverHelloMsg)
		serverSentRecordsParser.serverHello = serverHello
		if !ok {
			return nil, errors.New("TLS Parser: client hello message error")
		}
		serverSentRecordsParser.transcript.Write(serverHello.marshal())
		// fmt.Printf("TLS Parser: server hello record(without header): %x\n", serverHello.raw)

		//serverSentRecordsParser.deriveKeyAndIV(cipher, serverHandshakeSecret)
		serverSentRecordsParser.setKeyAndIV(cipher, serverHandshakeTrafficKey, serverHandshakeTrafficIV)
		msg, err = serverSentRecordsParser.parseServerEncryptedExtension(serverPath)
		encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
		serverSentRecordsParser.encryptedExtensions = encryptedExtensions
		if !ok {
			return nil, errors.New("TLS parser: encryption extension message error")
		}
		// fmt.Printf("TLS Parser: decrypted encrypted extensions: %x\n", encryptedExtensions.raw)
		serverSentRecordsParser.transcript.Write(encryptedExtensions.marshal())
		msg, err = serverSentRecordsParser.parseServerCertificate(serverPath)

		certVerify, ok := msg.(*certificateVerifyMsg)
		serverSentRecordsParser.certVerify = certVerify
		if !ok {
			return nil, errors.New("TLS Parser: encryption extension message error")
		}
		// fmt.Printf("TLS Parser: decrypted cert verify message: %x\n", certVerify.raw)

		msg, err = serverSentRecordsParser.parseFinishedMsg(serverPath)
		finished, ok := msg.(*finishedMsg)
		serverSentRecordsParser.finished = finished
		if !ok {
			return nil, errors.New("TLS Parser: sever finished error")
		}
		// fmt.Printf("TLS Parser: decrypted server finished message: %x\n", finished.raw)
		return serverSentRecordsParser, nil
	}
}

func (p *Parser) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		Roots:         p.certPool,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	var err error
	p.verifiedChains, err = certs[0].Verify(opts)
	if err != nil {
		return err
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	p.peerCertificates = certs

	return nil
}

func ParserFactory(caPath string, recordPath string) (serverSentRecordsParser *Parser, clientSentRecordsParser *Parser) {
	serverSentRecordsParser = new(Parser)
	clientSentRecordsParser = new(Parser)
	serverSentRecordsParser.offset = 0
	serverSentRecordsParser.handshakeComplete = false
	serverSentRecordsParser.vers = VersionTLS13
	clientSentRecordsParser.cipher = cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	serverSentRecordsParser.cipher = cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)

	caCert, _ := ioutil.ReadFile(caPath + "/ca.crt")
	caCertPool, _ := x509.SystemCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	serverSentRecordsParser.certPool = caCertPool
	clientSentRecordsParser.certPool = caCertPool
	serverSentRecordsParser.path = recordPath
	clientSentRecordsParser.path = recordPath
	return serverSentRecordsParser, clientSentRecordsParser
}

func (p *Parser) GetH0() []byte {

	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := cipher.hash.New()
	return transcript.Sum(nil)
}

func (p *Parser) GetH2() []byte {
	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := cipher.hash.New()
	transcript.Write(p.clientHello.marshal())
	transcript.Write(p.serverHello.marshal())
	return transcript.Sum(nil)
}

func (p *Parser) GetH3() []byte {
	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := cipher.hash.New()
	transcript.Write(p.clientHello.marshal())
	transcript.Write(p.serverHello.marshal())
	transcript.Write(p.encryptedExtensions.marshal())
	transcript.Write(p.certMsg.marshal())
	transcript.Write(p.certVerify.marshal())
	transcript.Write(p.finished.marshal())
	return transcript.Sum(nil)
}

func (p *Parser) GetH7() []byte {
	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := cipher.hash.New()
	transcript.Write(p.clientHello.marshal())
	transcript.Write(p.serverHello.marshal())
	transcript.Write(p.encryptedExtensions.marshal())
	transcript.Write(p.certMsg.marshal())
	transcript.Write(p.certVerify.marshal())
	return transcript.Sum(nil)
}
func (*Parser) GetL3() string {
	return "derived"
}

func (*Parser) GetL5() string {
	return serverHandshakeTrafficLabel
}

func (*Parser) GetL6() string {
	return "finished"
}
func (*Parser) GetL7() string {
	return clientApplicationTrafficLabel
}
func (*Parser) GetL8() string {
	return serverApplicationTrafficLabel
}

func (p *Parser) GetSF() []byte {
	return p.finished.verifyData
}
