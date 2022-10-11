# ORIGO


#### Contents
- [Introduction](#introduction)
- [Disclaimer](#disclaimer)
- [Structure and Development](#structure-and-development)
- [Command Line Toolkit](#command-line-toolkit)
- [Tutorials](#tutorials)
- [Evaluation](#evaluation)
- [Limitations](#limitations)
- [Citing](#citing)


## Introduction
_ORIGO_ is a decentralized oracle that doesn't rely on the trusted hardware and two-party computation. It allows users to prove the *provenance* of TLS records from a specific API and, in the meanwhile, prove the dynamic content fulfills a value constraint as pre-defined in a public policy in zero-knowledge.  It achieves confidentiality and integrity under certain honesty assumptions (e.g. honestly behaving proxy) which we define in the associated paper [ORIGO](https://link-to-origo.com). _ORIGO_ relies on a proxy sitting between the client user and the server hosting the API. The TLS stack running on the server does not require any modifications, making _ORIGO_ extendable to various existent APIs and web resources.


## Disclaimer
_ORIGO_ is a research project and its implementation has not undergone any security audit. Do not use _ORIGO_ in a production system or use it to process sensitive confidential data.


## Structure and Development
The structure of the project is as follows:
```
    ├── certs		# self-signed certificates for local development
    ├── commands	# command line toolkit logic
    ├── dependencies	# contains additional git submodules
    ├── docker		# containerization
    ├── docs		# documentation files
    ├── ledger_policy	# public policies defining API and constraint specifications
    ├── prover		# logic of http client to perform an API requests and prove policy compliance of response value
    ├── proxy		# tcp tunneling service for tls handshake and record layer traffic capturing and policy verification
    ├── server		# local https instance to serve sample traffic
    ├── transpiler	# policy to snark circuit generator translation
```
where we provide further details of sub-structures respectively in the [prover](./prover), [proxy](./proxy), and [server](./server) folders.

We quickly outline the key ideas behind the struture of the repository. For local development, developers can run the script `certs/cert.sh` to automatically generate self-signed root, server, and client certificates. The plan is to eventually seperate the folders `server`, `proxy`, and `prover` such that these folders can be executed individually on different machines for different deployment scenarios. The main idea behind the _ORIGO_ repository structure is that policies, circuits, and other configurations should be managed outside the folders `server`, `proxy`, and `prover`. Only strictly necessary files are supposed to be copied into individual `prover`, `proxy`, and `server` folders such that these folders can be copied and executed on different machines. Folders to manage policies or snark circuits are kept in separate locations (e.g. dependencies, ledger\_policy, transpiler, etc.). The `commands` folder maps modular functionalities from generating transcript data, parsing and extracting policy specific data, transpiling policies, compiling snark circuits, and generating proofs, to the _ORIGO_ command line binary such that developers can easily play around with different computation sequences and configurations. The `server` folder and server-commands are only required _ORIGO_ is executed entirely locally.


## Command Line Toolkit
_ORIGO_ is a command-line toolkit which allows users to (i) transpile policies into SNARK circuits, (ii) generate input data for policy compliant data provenance proofs from private APIs, and (iii) prove policy-compliant proofs in zero-knowledge. The high-level workflow of the _ORIGO_ command-line toolkit is as follows:

1. (proxy) start the proxy service
2. (server) start the server service (optional, required for local testing)
3. (prover) transpile public policy into a circuit generator
4. (prover) collect circuit input data by
	- refreshing API credentials (optional, if local deployment tutorial is used)
	- request API defined in policy and post-process tls and record layer traffic
5. (prover) generate snark-circuit in arithmetic representation and compute witness data
6. (prover) compute setup and generate zkp
7. (proxy) postprocess captured traffic transcript and collect zkp public input
8. (proxy) verify zkp


## Tutorials
We provide all details of how to execute _ORIGO_ in different deployments in our [tutorial](./docs/tutorials) guidelines. Before you start running the tutorials, please follow our [installation instructions](./docs/00_installation.md) to correctly set up the repository and its dependencies.


## Evaluation
To reproduce results provided in the research paper [ORIGO](https://link-to-origo.com), we provide an evaluation script [evaluation.sh](./evaluation.sh). The evaluation script can be executed by calling `./evaluation.sh` in the root location of this repository after installing the repository with the `./installation.sh` script as described [here](./docs/00_installation.md).


## Limitations
* _ORIGO_ currently supports off-chain zkp verification only and we plan to address on-chain zkp verification in the future. 
* The constraint system currently supported by _ORIGO_ public policies is very limited with value proofs of float greater than `GT`, float less than `LT` and string equality `EQ` and will be extended in the future.
* Adding flags for cmd toolkit input parameters.


## Citing
We welcome you to cite our [research paper](https://link-to-origo.com) if you are using _ORIGO_ in academic research.
```
@inproceedings{2022origo,
    author = {},
    title = {ORIGO: Proving Provenance of Sensitive Data},
    year = {2022},
    publisher = {},
    booktitle = {},
    location = {},
    series = {}
}
```

