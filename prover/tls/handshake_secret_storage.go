package tls

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
)

var fileName = struct {
	earlySecret        string
	derivedEarlySecret string

	clientHandshakeTrafficSecret string
	serverHandshakeTrafficKey    string
	serverHandshakeTrafficIV     string

	hkdfSHTSFirstBlock           string
	hkdfSHTSInnerHash            string
	serverHandshakeTrafficSecret string
	hkdfKFSFirstBlock            string
	hkdfKFSInnerHash             string

	hkdfSFFirstBlock  string
	hkdfSFInnerHash   string
	hkdfDHSFirstBlock string
	hkdfDHSInnerHash  string

	hkdfMSFirstBlock string
	hkdfMSInnerHash  string

	hkdfSATSFirstBlock string
	hkdfSATSInnerHash  string
	hkdfCATSInnerHash  string

	hkdfKSAPPFirstBlock   string
	hkdfKSAPPKeyInnerHash string
	hkdfKSAPPIVInnerHash  string

	hkdfKCAPPFirstBlock   string
	hkdfKCAPPKeyInnerHash string
	hkdfKCAPPIVInnerHash  string

	HandshakeSecret             string
	hkdfKFS                     string
	derivedHandshakeSecret      string
	masterSecret                string
	serverAppTrafficSecret      string
	clientAppTrafficSecret      string
	hkdfSF                      string
	serverApplicationTrafficIV  string
	serverApplicationTrafficKey string
	clientApplicationTrafficKey string
	clientApplicationTrafficIV  string

	galoisKeyCipher   string
	taskMaskCipher    string
	policyExtractJson string
}{
	earlySecret:        "EarlySecret",
	derivedEarlySecret: "DerivedEarlySecret",

	clientHandshakeTrafficSecret: "ClientHandshakeTrafficSecret",
	serverHandshakeTrafficKey:    "ServerHandshakeTrafficKey",
	serverHandshakeTrafficIV:     "ServerHandshakeTrafficIV",
	hkdfSF:                       "HkdfSF",
	serverApplicationTrafficIV:   "ServerApplicationTrafficIV",
	serverApplicationTrafficKey:  "ServerApplicationTrafficKey",
	clientApplicationTrafficKey:  "ClientApplicationTrafficKey",
	clientApplicationTrafficIV:   "ClientApplicationTrafficIV",

	hkdfSHTSFirstBlock:           "HkdfSHTSFirstBlock",
	hkdfSHTSInnerHash:            "HkdfSHTSInnerHash",
	serverHandshakeTrafficSecret: "ServerHandshakeTrafficSecret",
	hkdfKFSFirstBlock:            "HkdfKFSFirstBlock",
	hkdfKFSInnerHash:             "HkdfKSFInnerHash",

	hkdfSFFirstBlock:  "HkdfSFFirstBlock",
	hkdfSFInnerHash:   "HkdfSFInnerHash",
	hkdfDHSFirstBlock: "HkdfDHSFirstBlock",
	hkdfDHSInnerHash:  "HkdfDHSInnerHash",

	hkdfMSFirstBlock: "HkdfMSFirstBlock",
	hkdfMSInnerHash:  "HkdfMSInnerHash",

	hkdfSATSFirstBlock: "HkdfSATSFirstBlock",
	hkdfSATSInnerHash:  "HkdfSATSInnerHash",
	hkdfCATSInnerHash:  "HkdfCATSInnerHash",

	hkdfKSAPPFirstBlock:   "HkdfKSAPPFirstBlock",
	hkdfKSAPPKeyInnerHash: "HkdfKSAPPKeyInnerHash",
	hkdfKSAPPIVInnerHash:  "HkdfKSAPPIVInnerHash",

	hkdfKCAPPFirstBlock:   "HkdfKCAPPFirstBlock",
	hkdfKCAPPKeyInnerHash: "HkdfKCAPPKeyInnerHash",
	hkdfKCAPPIVInnerHash:  "HkdfKCAPPIVInnerHash",

	HandshakeSecret:        "HandshakeSecret",
	hkdfKFS:                "HkdfKFS",
	derivedHandshakeSecret: "DerivedHandshakeSecret",
	masterSecret:           "MasterSecret",
	serverAppTrafficSecret: "ServerAppTrafficSecret",
	clientAppTrafficSecret: "ClientAppTrafficSecret",
	galoisKeyCipher:        "GaloisKeyCipher",
	taskMaskCipher:         "TaskMaskCipher",
	policyExtractJson:      "PolicyExtractJson",
}

func jsonFileWrapper(file string) string {
	return file + ".json"
}

type PolicyExtract struct {
	StartBlockIdx int
	EndBlockIdx   int

	KeyValuePatternLength      int
	OffsetKeyValuePatternStart int
	OffsetValueStart           int
	ValueLength                int
	DotPosition                int
	Threshold                  string
	CompareMaxBitLen           int

	KeyValuePair         string
	KeyValueStartPattern string

	Seq                          string
	EarlySecret                  string
	DerivedEarlySecret           string
	HandshakeSecret              string
	ClientHandshakeTrafficSecret string
	ServerHandshakeTrafficSecret string
	ServerHandshakeTrafficKey    string
	ServerHandshakeTrafficIV     string
	HkdfSHTSFirstBlock           string
	HkdfDHSFirstBlock            string
	DerivedHandshakeSecret       string
	MasterSecret                 string
	HkdfMSFirstBlock             string
	HkdfKFSFirstBlock            string
	HkdfKFS                      string
	HkdfSFFirstBlock             string
	HkdfSF                       string
	HkdfSATSFirstBlock           string
	ClientAppTrafficSecret       string
	ServerAppTrafficSecret       string
	ServerApplicationTrafficKey  string
	ServerApplicationTrafficIV   string
	HkdfKSAPPFirstBlock          string
	ClientApplicationTrafficKey  string
	ClientApplicationTrafficIV   string
	HkdfKCAPPFirstBlock          string
	GaloisKeyCipher              string
	TaskMaskCipher               string
	PlaintextToProof             string

	HkdfSHTSInnerHash     string
	HkdfKFSInnerHash      string
	HkdfSFInnerHash       string
	HkdfDHSInnerHash      string
	HkdfMSInnerHash       string
	HkdfSATSInnerHash     string
	HkdfCATSInnerHash     string
	HkdfKSAPPKeyInnerHash string
	HkdfKSAPPIVInnerHash  string
	HkdfKCAPPKeyInnerHash string
	HkdfKCAPPIVInnerHash  string
	CiphertextToProof     string
}

type SharedPolicyExtract struct {
	StartBlockIdx              int
	EndBlockIdx                int
	KeyValuePatternLength      int
	OffsetKeyValuePatternStart int
	OffsetValueStart           int
	ValueLength                int
	DotPosition                int

	KeyValueStartPattern string

	Seq                       string
	ServerHandshakeTrafficKey string
	ServerHandshakeTrafficIV  string
	HkdfSHTSFirstBlock        string
	HkdfDHSFirstBlock         string
	HkdfMSFirstBlock          string
	HkdfKFSFirstBlock         string
	HkdfSFFirstBlock          string
	HkdfSATSFirstBlock        string
	HkdfKSAPPFirstBlock       string
	HkdfKCAPPFirstBlock       string
	GaloisKeyCipher           string
	TaskMaskCipher            string
}

func (ep *exchangePolicy) savePolicyExtractJson(name, loc string) error {

	// data disclosed to proxy
	sharedExtract := new(SharedPolicyExtract)
	sharedExtract.StartBlockIdx = ep.startBlockIdx
	sharedExtract.EndBlockIdx = ep.endBlockIdx
	sharedExtract.OffsetKeyValuePatternStart = ep.startIdxKeyValuePair - ep.startBlockIdx*16
	sharedExtract.OffsetValueStart = ep.startIdxValue + ep.startIdxKeyValuePair - ep.startBlockIdx*16 + 1
	sharedExtract.KeyValueStartPattern = ep.keyValueStartPattern
	sharedExtract.KeyValuePatternLength = ep.endIdxKeyValuePair - ep.startIdxKeyValuePair
	sharedExtract.ValueLength = ep.endIdxValue - ep.startIdxValue - 2
	sharedExtract.DotPosition = ep.DotPosition
	//sharedExtract.KeyValuePair = hex.EncodeToString(ep.keyValuePair)

	sharedExtract.Seq = hex.EncodeToString(ep.seq)
	sharedExtract.ServerHandshakeTrafficKey = hex.EncodeToString(ep.storage.serverHandshakeTrafficKey)
	sharedExtract.ServerHandshakeTrafficIV = hex.EncodeToString(ep.storage.serverHandshakeTrafficIV)
	sharedExtract.HkdfSHTSFirstBlock = hex.EncodeToString(ep.storage.hkdfSHTSFirstBlock)
	sharedExtract.HkdfDHSFirstBlock = hex.EncodeToString(ep.storage.hkdfDHSFirstBlock)
	sharedExtract.HkdfMSFirstBlock = hex.EncodeToString(ep.storage.hkdfMSFirstBlock)
	sharedExtract.HkdfKFSFirstBlock = hex.EncodeToString(ep.storage.hkdfKFSFirstBlock)
	sharedExtract.HkdfSFFirstBlock = hex.EncodeToString(ep.storage.hkdfSFFirstBlock)
	sharedExtract.HkdfSATSFirstBlock = hex.EncodeToString(ep.storage.hkdfSATSFirstBlock)
	sharedExtract.HkdfKSAPPFirstBlock = hex.EncodeToString(ep.storage.hkdfKSAPPFirstBlock)
	sharedExtract.HkdfKCAPPFirstBlock = hex.EncodeToString(ep.storage.hkdfKCAPPFirstBlock)
	sharedExtract.GaloisKeyCipher = hex.EncodeToString(ep.storage.galoisKeyCipher)
	sharedExtract.TaskMaskCipher = hex.EncodeToString(ep.storage.taskMaskCipher)

	// wiriting policy extract json shared to file
	file, err := json.MarshalIndent(sharedExtract, "", " ")
	if err == nil {
		err = ioutil.WriteFile(loc+jsonFileWrapper(name+"Shared"), file, 0644)
	}
	// return if json writing failed
	if err != nil {
		return err
	}

	// data stored locally
	extract := new(PolicyExtract)
	extract.StartBlockIdx = ep.startBlockIdx
	extract.EndBlockIdx = ep.endBlockIdx
	extract.OffsetKeyValuePatternStart = ep.startIdxKeyValuePair - ep.startBlockIdx*16
	extract.OffsetValueStart = ep.startIdxValue + ep.startIdxKeyValuePair - ep.startBlockIdx*16 + 1
	extract.KeyValueStartPattern = ep.keyValueStartPattern
	extract.KeyValuePatternLength = ep.endIdxKeyValuePair - ep.startIdxKeyValuePair
	extract.ValueLength = ep.endIdxValue - ep.startIdxValue - 2
	extract.DotPosition = ep.DotPosition
	extract.KeyValuePair = hex.EncodeToString(ep.keyValuePair)
	extract.Seq = hex.EncodeToString(ep.seq)
	extract.EarlySecret = hex.EncodeToString(ep.storage.earlySecret)
	extract.DerivedEarlySecret = hex.EncodeToString(ep.storage.derivedEarlySecret)
	extract.HandshakeSecret = hex.EncodeToString(ep.storage.handshakeSecret)
	extract.ClientHandshakeTrafficSecret = hex.EncodeToString(ep.storage.clientHandshakeTrafficSecret)
	extract.ServerHandshakeTrafficSecret = hex.EncodeToString(ep.storage.serverHandshakeTrafficSecret)
	extract.ServerHandshakeTrafficKey = hex.EncodeToString(ep.storage.serverHandshakeTrafficKey)
	extract.ServerHandshakeTrafficIV = hex.EncodeToString(ep.storage.serverHandshakeTrafficIV)
	extract.HkdfSHTSFirstBlock = hex.EncodeToString(ep.storage.hkdfSHTSFirstBlock)
	extract.HkdfDHSFirstBlock = hex.EncodeToString(ep.storage.hkdfDHSFirstBlock)
	extract.DerivedHandshakeSecret = hex.EncodeToString(ep.storage.derivedHandshakeSecret)
	extract.MasterSecret = hex.EncodeToString(ep.storage.masterSecret)
	extract.HkdfMSFirstBlock = hex.EncodeToString(ep.storage.hkdfMSFirstBlock)
	extract.HkdfKFSFirstBlock = hex.EncodeToString(ep.storage.hkdfKFSFirstBlock)
	extract.HkdfKFS = hex.EncodeToString(ep.storage.hkdfKFS)
	extract.HkdfSFFirstBlock = hex.EncodeToString(ep.storage.hkdfSFFirstBlock)
	extract.HkdfSF = hex.EncodeToString(ep.storage.hkdfSF)
	extract.HkdfSATSFirstBlock = hex.EncodeToString(ep.storage.hkdfSATSFirstBlock)
	extract.ClientAppTrafficSecret = hex.EncodeToString(ep.storage.clientAppTrafficSecret)
	extract.ServerAppTrafficSecret = hex.EncodeToString(ep.storage.serverAppTrafficSecret)
	extract.ServerApplicationTrafficKey = hex.EncodeToString(ep.storage.serverApplicationTrafficKey)
	extract.ServerApplicationTrafficIV = hex.EncodeToString(ep.storage.serverApplicationTrafficIV)
	extract.HkdfKSAPPFirstBlock = hex.EncodeToString(ep.storage.hkdfKSAPPFirstBlock)
	extract.ClientApplicationTrafficKey = hex.EncodeToString(ep.storage.clientApplicationTrafficKey)
	extract.ClientApplicationTrafficIV = hex.EncodeToString(ep.storage.clientApplicationTrafficIV)
	extract.HkdfKCAPPFirstBlock = hex.EncodeToString(ep.storage.hkdfKCAPPFirstBlock)
	extract.GaloisKeyCipher = hex.EncodeToString(ep.storage.galoisKeyCipher)
	extract.TaskMaskCipher = hex.EncodeToString(ep.storage.taskMaskCipher)
	extract.PlaintextToProof = hex.EncodeToString(ep.storage.plaintextToProof)

	extract.HkdfSHTSInnerHash = hex.EncodeToString(ep.storage.HkdfSHTSInnerHash)
	extract.HkdfKFSInnerHash = hex.EncodeToString(ep.storage.HkdfKFSInnerHash)
	extract.HkdfSFInnerHash = hex.EncodeToString(ep.storage.HkdfSFInnerHash)
	extract.HkdfDHSInnerHash = hex.EncodeToString(ep.storage.HkdfDHSInnerHash)
	extract.HkdfMSInnerHash = hex.EncodeToString(ep.storage.HkdfMSInnerHash)
	extract.HkdfSATSInnerHash = hex.EncodeToString(ep.storage.HkdfSATSInnerHash)
	extract.HkdfCATSInnerHash = hex.EncodeToString(ep.storage.HkdfCATSInnerHash)
	extract.HkdfKSAPPKeyInnerHash = hex.EncodeToString(ep.storage.HkdfKSAPPKeyInnerHash)
	extract.HkdfKSAPPIVInnerHash = hex.EncodeToString(ep.storage.HkdfKSAPPIVInnerHash)
	extract.HkdfKCAPPKeyInnerHash = hex.EncodeToString(ep.storage.HkdfKCAPPKeyInnerHash)
	extract.HkdfKCAPPIVInnerHash = hex.EncodeToString(ep.storage.HkdfKCAPPIVInnerHash)
	extract.CiphertextToProof = hex.EncodeToString(ep.storage.CiphertextToProof)

	extract.Threshold = ep.Threshold
	extract.CompareMaxBitLen = ep.CompareMaxBitLen

	// writing policy extract json to file
	file, err = json.MarshalIndent(extract, "", " ")
	if err == nil {
		err = ioutil.WriteFile(loc+jsonFileWrapper(name), file, 0644)
	}
	return err
}
