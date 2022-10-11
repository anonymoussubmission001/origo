## Prover Structure
The file structure of the prover folder is as follows:
```
    ├── credentials		# private credential management
    ├── gitcoin_server		# local instance exposing gitcoin passport management
    ├── local_storage		# prover specific data extracted from tls session to API
    ├── tls			# modified TLS standard library
    ├── zksnark_build		# essential files needed to compute zk proof and compile snark circuits
    ├── config.go		# manage prover local configurations
    ├── config.json		# prover local configurations
    ├── generate_proof.go	# functions which interact with `zksnark_build` to compile and prove zksnark circuits
    ├── request_api.go		# functions to interact with APIs and collect handshake and record layer data.
```
We explain the purpose of the different subfolders in the following sections.

### credentials
The credentials folder maintains configurations and private credentials (e.g. access\_tokens) of the prover. Since credential data among different APIs varies drastically, structural changes of this folder can be expected in the future. As of now, configurations od APIs specify URLs required to refresh access tokens and private parts of record layer API URLs.

### gitcoin\_server
The webserver exposes a react frontend which lets users create stamps to their gitcoin passport running on Ceramic Mainnet. Users can create gitcoin passports via the fronend on Ceramic Mainnet and get their streamID. When adding a stamp to the streamID on Ceramic, users can make use of _ORIGO_ policies to sign and prove confidential statements (e.g. currently paypal balance policy compliance).

### local\_storage
Collection of TLS handshake and record layer data extracted by the prover according to the specified policy. The policy extract JSON file contains all information required by the prover to compile a zk-snark circuit and compute the witness values with the currently supported Jsnark framework. The information of the shared policy extract must be send to the proxy and contains public input information required for the zkp verification.

#### About Shared Policy Extract JSON
The prover reveals the following element to the proxy. Those parameters are generated automatically by the prover. The following content will be available to the proxy. It's only an explanation of the usage for each field.

- *StartBlockIdx*: the starting index of the key-value pair in the AES block (not including the TLS record head)
- *EndBlockIdx*: the ending index of the key-value pair in the AES block (not including the TLS record head)
- *KeyValuePatternLength*: the length of key-value pattern (can be calculated startIdxKeyValuePair - startBlockIdx\*16)
- *OffsetKeyValuePatternStart*: the offset of key-value pattern in the AES block (min value could be 0)
- *OffsetValueStart*: the offset of value in the AES block (can be calculated by adding OffsetKeyValuePatternStart and the length of  KeyValueStartPattern)
- *ValueLength*: the floating-point value length including Mantissa and dot, e.g., the value length of 380002.2 is 7
- *DotPosition*: the dot position in the key-value pattern of a floating-point number, e.g., 5 is the dot position for 38002.2
- *KeyValueStartPattern*: the starting pattern of the key-value pair, which begins with double quotes (") and ends with double quotes followed a comma(",)
- *Seq*: the sequence counter of the appeared key-value pair in the TLS records
- *ServerHandshakeTrafficKey*: the server handshake traffic key
- *ServerHandshakeTrafficIV*: the client handshake traffic key
- *HkdfSHTSFirstBlock*: the hash of the first sha256 block of the HKDF SHTS for KDC-OPT
- *HkdfDHSFirstBlock*: the hash of the first sha256 block of the HKDF dHS for KDC-OPT
- *HkdfMSFirstBlock*: the hash of the first sha256 block of the HKDF MS for KDC-OPT
- *HkdfKFSFirstBlock*: the hash of the first sha256 block of the HKDF KFS for KDC-OPT
- *HkdfSFFirstBlock*: the hash of the first sha256 block of the HKDF KFS for KDC-OPT
- *HkdfSATSFirstBlock*: the hash of the first sha256 block of the HKDF KFS for KDC-OPT
- *HkdfKSAPPFirstBlock*: the hash of the first sha256 block of the HKDF KSAPP for KDC-OPT
- *HkdfKCAPPFirstBlock*: the hash of the first sha256 block of the HKDF KCAPP for KDC-OPT
- *GaloisKeyCipher*: galois key (encrypted) for KDC-OPT
- *TaskMaskCipher*: task mask (encrypted) for KDC-OPT

### tls
Modified Golang TLS standard library [crypto/tls](https://pkg.go.dev/crypto/tls). We provide further details on main changes [here](../docs/02_main_changes.md).

### zksnark\_build
Folder which groups zksnark specific dependencies required by the prover. Currently, the folder contains pre-compiled libsnark binaries and jsnark generated java generator files to compile zksnark circuits. Information on main changes of Jsnark and Libsnark can be found [here](../docs/02_main_changes.md).

### Remaining Todos
- add command to send shared policy extract JSON data to an endpoint provided by the proxy.

