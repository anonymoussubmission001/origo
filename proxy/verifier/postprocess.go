package verifier

import (
	// "fmt"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	lp "github.com/anonymoussubmission001/origo/ledger_policy"

	// TODO: get rid of this import
	tls "github.com/anonymoussubmission001/origo/prover/tls"
)

// ************** start PP struct **************

type PP struct {
	Policy         lp.Policy
	Config         VerifierConfig
	PolicyFileName string
	SharedExtract  tls.SharedPolicyExtract
}

func NewPP(policyFileName string) (*PP, error) {

	// init empty ApiClient
	p := new(PP)

	// open ledger policy and store in proxy Policy struct
	policyFile, err := os.Open("ledger_policy/" + policyFileName + ".json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer policyFile.Close()
	byteValue, _ := ioutil.ReadAll(policyFile)
	json.Unmarshal(byteValue, &p.Policy)

	// open local verifier config and deserialize to struct
	configFile, err := os.Open("proxy/verifier/config.json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer configFile.Close()
	byteValue2, _ := ioutil.ReadAll(configFile)
	json.Unmarshal(byteValue2, &p.Config)

	// set inputs to client struct
	p.PolicyFileName = policyFileName

	// read in to-be-shared extracted tls and record data
	shareFile, err := os.Open(p.Config.ProverShareFilePath + ".json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer shareFile.Close()
	byteValue3, _ := ioutil.ReadAll(shareFile)
	json.Unmarshal(byteValue3, &p.SharedExtract)

	return p, nil
}

func (p *PP) PostProcess() error {

	// prepare policy values
	api := p.Policy.APIs[0]
	constraint := p.Policy.Constraints[0]
	// proxy := p.Policy.Proxies[0]

	// debugging
	// fmt.Println("Policy:", p.Policy)
	// fmt.Println("Verifier Config:", p.Config)
	// fmt.Println("SharedPolicyExtract:", p.SharedExtract)

	// decode SHTK and SHTIV
	ServerHandshakeTrafficKey, _ := hex.DecodeString(p.SharedExtract.ServerHandshakeTrafficKey)
	ServerHandshakeTrafficIV, _ := hex.DecodeString(p.SharedExtract.ServerHandshakeTrafficIV)

	// parse tls captured content
	tlsp, err := tls.RunTLSParser(p.Config.CertificatePath, p.Config.StoragePath, ServerHandshakeTrafficKey, ServerHandshakeTrafficIV, p.Config.ServerSentRecordsFileName, p.Config.ProverSentRecordsFileName)
	if err != nil {
		log.Println("TLS parser: please check whether prover shared the up-to-date PolicyExtractJsonShared.json. " + "This error could be caused by malicious Prover!")
		return err
	}

	// prepare ZKP
	// jsonData = p.SharedExtract; pJson (policyJson struct) = p.Policy

	sbf := new(StatementByteFormat)
	// pd.printKDCOPTResult(p, jsonData)

	// translate shared values to public input struct
	sbf.prepareKDCInnerHash(tlsp, p.SharedExtract)
	seq, _ := strconv.ParseUint(p.SharedExtract.Seq, 16, 32)
	sbf.GaloisKeyCipher, _ = hex.DecodeString(p.SharedExtract.GaloisKeyCipher)
	sbf.TaskMaskCipher, _ = hex.DecodeString(p.SharedExtract.TaskMaskCipher)
	sbf.StartBlockIdx = p.SharedExtract.StartBlockIdx
	sbf.EndBlockIdx = p.SharedExtract.EndBlockIdx
	sbf.OffsetKeyValuePatternStart = p.SharedExtract.OffsetKeyValuePatternStart
	sbf.KeyValuePatternLength = p.SharedExtract.KeyValuePatternLength
	sbf.OffsetValueStart = p.SharedExtract.OffsetValueStart
	sbf.ValueLength = p.SharedExtract.ValueLength
	sbf.DotPosition = p.SharedExtract.DotPosition
	sbf.SeqCounter = p.SharedExtract.Seq

	// take over public input from policy
	if constraint.Constraint == "GT" || constraint.Constraint == "LT" {
		tmp := strings.Split(constraint.Value, ".")
		sbf.Threshold = tmp[0] + tmp[1]
	} else {
		sbf.Threshold = constraint.Value
	}
	// sbf.Threshold = pJson.Threshold
	// sbf.CompareMaxBitLen = pJson.CompareMaxBitLen
	sbf.CompareMaxBitLen = 126
	sbf.HkdfSF = hex.EncodeToString(tlsp.GetSF())

	// additional safety checks
	if !strings.HasSuffix(api.Pattern, "\"[0-9]+.[0-9]+\",") {
		log.Println("pattern not supported currently, value should be a floating point")
		return errors.New("pattern not supported currently, value should be a floating point")
	} else {
		matching, err := regexp.MatchString(strings.TrimSuffix(api.Pattern, "\"[0-9]+.[0-9]+\","), p.SharedExtract.KeyValueStartPattern)
		if err == nil {
			if matching {
				// log.Println("matching success, accept shared PolicyExtractJsonShared.json from Prover by Proxy")
			} else {
				log.Println("matching failed")
				return errors.New("matching failed.")
			}
		} else {
			log.Println("invalid regex pattern in policy", err)
			return errors.New("invalid regexp pattern in policy")
		}

	}
	sbf.KeyValueStartPattern = p.SharedExtract.KeyValueStartPattern

	// verify aes gcm tag by computing it
	_, sbf.CiphertextToProof = tlsp.VerifyGCMTag(int(seq), sbf.StartBlockIdx, sbf.EndBlockIdx, sbf.TaskMaskCipher, sbf.GaloisKeyCipher)

	// save public input to file
	err = sbf.saveStatement(p.Config.StoragePath, p.Config.PublicInputFileName)
	if err != nil {
		log.Println("sbf.saveStatement() error:", err)
		return err
	}

	return nil
}

// ************* end PP struct **********************

// ************* start StatementByteFormat struct *****************

type StatementByteFormat struct {
	StartBlockIdx              int
	EndBlockIdx                int
	OffsetKeyValuePatternStart int
	KeyValuePatternLength      int
	OffsetValueStart           int
	ValueLength                int
	DotPosition                int

	CompareMaxBitLen     int
	Threshold            string
	HkdfSF               string
	SeqCounter           string
	KeyValueStartPattern string

	CiphertextToProof            []byte
	GaloisKeyCipher              []byte
	TaskMaskCipher               []byte
	ServerHandshakeTrafficSecret []byte

	HkdfSHTSInnerHash []byte

	HkdfKFSInnerHash []byte

	HkdfSFInnerHash []byte

	HkdfDHSInnerHash []byte

	HkdfMSInnerHash []byte

	HkdfSATSInnerHash []byte
	HkdfCATSInnerHash []byte

	HkdfKSAPPKeyInnerHash []byte
	HkdfKSAPPIVInnerHash  []byte

	HkdfKCAPPKeyInnerHash []byte
	HkdfKCAPPIVInnerHash  []byte
}

func (pd *StatementByteFormat) prepareKDCInnerHash(p *tls.Parser, jsonData tls.SharedPolicyExtract) {
	data, _ := tls.HKDFExpandInnerHashInputBuilder(p.GetL5(), p.GetH2(), sha256.Size)
	pd.HkdfSHTSInnerHash = postprocessInnerFirstBlockWithInput(data, "SHTS", jsonData.HkdfSHTSFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder(p.GetL6(), nil, sha256.Size)
	pd.HkdfKFSInnerHash = postprocessInnerFirstBlockWithInput(data, "kfs", jsonData.HkdfKFSFirstBlock)
	data = p.GetH7()
	pd.HkdfSFInnerHash = postprocessInnerFirstBlockWithInput(data, "sf", jsonData.HkdfSFFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder(p.GetL3(), p.GetH0(), sha256.Size)
	pd.HkdfDHSInnerHash = postprocessInnerFirstBlockWithInput(data, "dHS", jsonData.HkdfDHSFirstBlock)
	data = make([]byte, crypto.SHA256.Size())
	pd.HkdfMSInnerHash = postprocessInnerFirstBlockWithInput(data, "MS", jsonData.HkdfMSFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder(p.GetL8(), p.GetH3(), sha256.Size)
	pd.HkdfSATSInnerHash = postprocessInnerFirstBlockWithInput(data, "SATS", jsonData.HkdfSATSFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder(p.GetL7(), p.GetH3(), sha256.Size)
	pd.HkdfCATSInnerHash = postprocessInnerFirstBlockWithInput(data, "CATS", jsonData.HkdfSATSFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder("key", nil, 16)
	pd.HkdfKSAPPKeyInnerHash = postprocessInnerFirstBlockWithInput(data, "k_SAPP Key", jsonData.HkdfKSAPPFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder("iv", nil, 12)
	pd.HkdfKSAPPIVInnerHash = postprocessInnerFirstBlockWithInput(data, "k_SAPP IV", jsonData.HkdfKSAPPFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder("key", nil, 16)
	pd.HkdfKCAPPKeyInnerHash = postprocessInnerFirstBlockWithInput(data, "k_CAPP Key", jsonData.HkdfKCAPPFirstBlock)
	data, _ = tls.HKDFExpandInnerHashInputBuilder("iv", nil, 12)
	pd.HkdfKCAPPIVInnerHash = postprocessInnerFirstBlockWithInput(data, "k_CAPP IV", jsonData.HkdfKCAPPFirstBlock)
}

func (sbf *StatementByteFormat) saveStatement(storagePath, publicInputFileName string) error {
	statement := new(Statement)
	statement.HkdfKSAPPKeyInnerHash = hex.EncodeToString(sbf.HkdfKSAPPKeyInnerHash)
	statement.StartBlockIdx = sbf.StartBlockIdx
	statement.EndBlockIdx = sbf.EndBlockIdx
	statement.GaloisKeyCipher = hex.EncodeToString(sbf.GaloisKeyCipher)
	statement.TaskMaskCipher = hex.EncodeToString(sbf.TaskMaskCipher)
	statement.HkdfSHTSInnerHash = hex.EncodeToString(sbf.HkdfSHTSInnerHash)
	statement.HkdfKFSInnerHash = hex.EncodeToString(sbf.HkdfKFSInnerHash)
	statement.HkdfSFInnerHash = hex.EncodeToString(sbf.HkdfSFInnerHash)
	statement.HkdfDHSInnerHash = hex.EncodeToString(sbf.HkdfDHSInnerHash)
	statement.HkdfMSInnerHash = hex.EncodeToString(sbf.HkdfMSInnerHash)
	statement.HkdfSATSInnerHash = hex.EncodeToString(sbf.HkdfSATSInnerHash)
	statement.HkdfCATSInnerHash = hex.EncodeToString(sbf.HkdfCATSInnerHash)
	statement.HkdfKSAPPKeyInnerHash = hex.EncodeToString(sbf.HkdfKSAPPKeyInnerHash)
	statement.HkdfKSAPPIVInnerHash = hex.EncodeToString(sbf.HkdfKSAPPIVInnerHash)
	statement.HkdfKCAPPKeyInnerHash = hex.EncodeToString(sbf.HkdfKCAPPKeyInnerHash)
	statement.HkdfKCAPPIVInnerHash = hex.EncodeToString(sbf.HkdfKCAPPIVInnerHash)
	statement.CiphertextToProof = hex.EncodeToString(sbf.CiphertextToProof)
	statement.OffsetKeyValuePatternStart = sbf.OffsetKeyValuePatternStart
	statement.KeyValuePatternLength = sbf.KeyValuePatternLength
	statement.OffsetValueStart = sbf.OffsetValueStart
	statement.ValueLength = sbf.ValueLength
	statement.DotPosition = sbf.DotPosition
	statement.CompareMaxBitLen = sbf.CompareMaxBitLen
	statement.Threshold = sbf.Threshold
	statement.HkdfSF = sbf.HkdfSF
	statement.SeqCounter = sbf.SeqCounter
	statement.KeyValuePatternLength = sbf.KeyValuePatternLength
	statement.KeyValueStartPattern = sbf.KeyValueStartPattern

	file, err := json.MarshalIndent(statement, "", " ")
	if err == nil {
		err = ioutil.WriteFile(storagePath+JsonFileWrapper(publicInputFileName), file, 0644)
	}
	return err
}

// *************** end StatementByteFormat struct ********************

// *************** start Statement struct *****************

type Statement struct {
	StartBlockIdx              int
	EndBlockIdx                int
	OffsetKeyValuePatternStart int
	KeyValuePatternLength      int
	OffsetValueStart           int
	ValueLength                int
	DotPosition                int

	CompareMaxBitLen     int
	Threshold            string
	SeqCounter           string
	HkdfSF               string
	KeyValueStartPattern string

	CiphertextToProof string

	GaloisKeyCipher string
	TaskMaskCipher  string

	HkdfSHTSInnerHash string

	HkdfKFSInnerHash string

	HkdfSFInnerHash string

	HkdfDHSInnerHash string

	HkdfMSInnerHash string

	HkdfSATSInnerHash string
	HkdfCATSInnerHash string

	HkdfKSAPPKeyInnerHash string
	HkdfKSAPPIVInnerHash  string

	HkdfKCAPPKeyInnerHash string
	HkdfKCAPPIVInnerHash  string
}

// *************** end Statement struct ****************

// *************** helper functions ********************
func JsonFileWrapper(file string) string {
	return file + ".json"
}

func postprocessInnerFirstBlockWithInput(data []byte, desc string, firstBlockStr string) (inner []byte) {
	hmacMD := new(tls.HmacMD)
	firstBlock, _ := hex.DecodeString(firstBlockStr)
	hmacMD.CompInnerHash(data, firstBlock)
	return hmacMD.GetHMACInner()
}
