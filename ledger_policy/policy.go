package ledger_policy

type API struct {
	Url		string		`json:"url"`
	ContentType	string		`json:"content-type"`
	Pattern		string		`json:"pattern"`
	Creds		bool		`json:"creds"`
}

type Constraint struct {
	Value		string		`json:"value"`
	Constraint	string		`json:"constraint"`
}

type Proxy struct {
	Host		string		`json:"host"`
	Port		string		`json:"port"`
	Mode		string		`json:"mode"`
	PubKey		string		`json:"pubKey"`
	Algorithm	string		`json:"algorithm"`
}

type Policy struct {
	APIs		[]API		`json:"apis"`
	Constraints	[]Constraint	`json:"constraints"`
	Proxies		[]Proxy		`json:"proxies"`
}

