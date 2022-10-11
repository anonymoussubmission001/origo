package prover

type ProverConfig struct {
	ZkSnarkBuildPath		string
	StoragePath			string
	ProveSentRecordsFileName	string
	ServerSentRecordsFileName	string
	PathCaCrt			string
	PathProverPem			string
	PathProverKey			string
	PolicyPath			string
	Rebuild				bool
}

