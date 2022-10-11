package verifier

import (
	"os"
	"log"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"os/exec"
)

type Verifier struct {
	PublicInput	Statement
	Config		VerifierConfig
}

func NewVerifier() (*Verifier, error) {

	// init verifier
	v := new(Verifier)

	// read in configs and deserialize into struct
	configFile, err := os.Open("proxy/verifier/config.json")
	if err != nil {
	    log.Println("os.Open() error", err)
	    return nil, err
	}
	defer configFile.Close()
	byteValue2, _ := ioutil.ReadAll(configFile)
	json.Unmarshal(byteValue2, &v.Config)

	// read in public input
	piFile, err := os.Open(v.Config.StoragePath+v.Config.PublicInputFileName+".json")
        if err != nil {
            log.Println("os.Open() error", err)
            return nil, err
        }
        defer piFile.Close()
        byteValue3, _ := ioutil.ReadAll(piFile)
        json.Unmarshal(byteValue3, &v.PublicInput)

	return v, nil
}

func (v *Verifier) Verify() error {

	// value shortening
	spe := v.PublicInput

	// zkp verification command
	cmd := exec.Command("./jsnark_interface/bin/run_proxy_verify", spe.HkdfSHTSInnerHash, spe.HkdfKFSInnerHash, spe.HkdfSFInnerHash, spe.HkdfDHSInnerHash, spe.HkdfMSInnerHash, spe.HkdfSATSInnerHash, spe.HkdfCATSInnerHash, spe.HkdfKSAPPKeyInnerHash, spe.HkdfKSAPPIVInnerHash, spe.HkdfKCAPPKeyInnerHash, spe.HkdfKCAPPIVInnerHash, spe.HkdfSF, spe.CiphertextToProof, spe.SeqCounter, spe.Threshold)
	cmd.Dir = v.Config.ZkSnarkBuildPath

	// execute command
	data, err := cmd.Output()
	if err != nil {
		log.Println("cmd.Output() error:", err)
		return err
	}

	// print output
	fmt.Println(string(data))

	return nil
}

