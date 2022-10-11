package verifier

type VerifierConfig struct {
	// config parameters of proxy
	StoragePath			string
	ProverSentRecordsFileName	string
	ServerSentRecordsFileName	string
	CertificatePath			string
	PublicInputFileName		string
	ZkSnarkBuildPath		string

	// prover information, values collected from prover folder need to be send to the proxy in a future update
	ProverShareFilePath		string
}

