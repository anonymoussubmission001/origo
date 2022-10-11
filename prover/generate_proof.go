package prover

import (
	"log"
	// "fmt"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"

	lp "github.com/anonymoussubmission001/origo/ledger_policy"
	tls "github.com/anonymoussubmission001/origo/prover/tls"
)

type Prover struct {
	Policy            lp.Policy
	Config            ProverConfig
	PolicyExtract     tls.PolicyExtract
	PolicyFileName    string
	GeneratorFileName string
}

func NewProver(policyFileName string, generatorFileName string, configOnly bool) (*Prover, error) {

	// init prover
	prover := new(Prover)

	// open policy and deserialize to struct
	if !configOnly {
		policyFile, err := os.Open("ledger_policy/" + policyFileName + ".json")
		if err != nil {
			log.Println("os.Open() error", err)
			return nil, err
		}
		defer policyFile.Close()
		byteValue, _ := ioutil.ReadAll(policyFile)
		json.Unmarshal(byteValue, &prover.Policy)
	}

	prover.PolicyFileName = policyFileName
	prover.GeneratorFileName = generatorFileName

	// open config and deserialize to struct
	configFile, err := os.Open("prover/config.json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer configFile.Close()
	byteValue2, _ := ioutil.ReadAll(configFile)
	json.Unmarshal(byteValue2, &prover.Config)

	// read in extracted tls values (get deployment data)
	if !configOnly {
		extractFile, err := os.Open(prover.Config.StoragePath + "PolicyExtractJson.json")
		if err != nil {
			log.Println("os.Open() error", err)
			return nil, err
		}
		defer extractFile.Close()
		byteValue3, _ := ioutil.ReadAll(extractFile)
		json.Unmarshal(byteValue3, &prover.PolicyExtract)
	}

	return prover, nil
}

func (p *Prover) CompileCircuit() error {

	// shortening
	pe := p.PolicyExtract

	// parse policy extract values
	blockNr := strconv.Itoa(pe.EndBlockIdx - pe.StartBlockIdx)
	startBlockIdx := strconv.Itoa(pe.StartBlockIdx)
	keyValuePairLen := strconv.Itoa(pe.KeyValuePatternLength)
	offsetKeyValuePair := strconv.Itoa(pe.OffsetKeyValuePatternStart)
	offsetValue := strconv.Itoa(pe.OffsetValueStart)
	floatStringLen := strconv.Itoa(pe.ValueLength)
	dotIdx := strconv.Itoa(pe.DotPosition)
	keyValueStartPattern := pe.KeyValueStartPattern

	HSStr := pe.HandshakeSecret

	SHTSInnerHashStr := pe.HkdfSHTSInnerHash
	kfsInnerHashStr := pe.HkdfKFSInnerHash
	sfInnerHashStr := pe.HkdfSFInnerHash

	dHSInnerHashStr := pe.HkdfDHSInnerHash
	MSHSInnerHashStr := pe.HkdfMSInnerHash
	SATSInnerHashStr := pe.HkdfSATSInnerHash
	CATSInnerHashStr := pe.HkdfCATSInnerHash
	kSAPPKeyInnerHashStr := pe.HkdfKSAPPKeyInnerHash
	kSAPPIVInnerHashStr := pe.HkdfKSAPPIVInnerHash
	kCAPPKeyInnerHashStr := pe.HkdfKCAPPKeyInnerHash
	kCAPPIVInnerHashStr := pe.HkdfKCAPPIVInnerHash
	plaintextStr := pe.PlaintextToProof
	SFStr := pe.HkdfSF
	SeqCounterStr := pe.Seq
	ciphertextStr := pe.CiphertextToProof

	// threshold := pJson.Threshold // scaled
	threshold := pe.Threshold
	compareMaxLen := strconv.Itoa(pe.CompareMaxBitLen)

	// command to build .arth .in files
	runCmd := exec.Command("java", "-cp", "bin", "examples.generators.transpiled."+p.GeneratorFileName, blockNr, startBlockIdx, keyValuePairLen, offsetKeyValuePair, offsetValue, floatStringLen, dotIdx, keyValueStartPattern, HSStr, SHTSInnerHashStr, kfsInnerHashStr, sfInnerHashStr, dHSInnerHashStr, MSHSInnerHashStr, SATSInnerHashStr, CATSInnerHashStr, kSAPPKeyInnerHashStr, kSAPPIVInnerHashStr, kCAPPKeyInnerHashStr, kCAPPIVInnerHashStr, plaintextStr, SFStr, SeqCounterStr, ciphertextStr, threshold, compareMaxLen)
	// log.Println("cmd:::", runCmd)
	runCmd.Dir = p.Config.ZkSnarkBuildPath + "/jsnark"

	// build circuit
	data, err := runCmd.Output()
	if err != nil {
		log.Println("runCmd.Output error:", err)
		return err
	}
	log.Println(string(data))

	return nil
}

func (p *Prover) GenerateProof() error {

	// ZK snark setup and proof generation
	setupCmd := exec.Command("./jsnark_interface/bin/run_generate_prove",
		"./jsnark/"+p.GeneratorFileName+"_Circuit.arith", "./jsnark/"+p.GeneratorFileName+"_Circuit.in")
	setupCmd.Dir = p.Config.ZkSnarkBuildPath

	// compute setup and proof
	data, err := setupCmd.Output()
	if err != nil {
		log.Println("setupCmd.Output() error:", err)
		return err
	}

	// print output
	log.Println(string(data))

	return nil
}
