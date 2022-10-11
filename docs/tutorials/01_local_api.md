## Tutorial 01: Local Execution


#### Step 1: Policy inspection and transpilation
The first tutorial starts all services locally on a single machine. No credentials are required on the prover side and we demonstrate the local deployment of _ORIGO_ by introducing the public policy `ledger_policy/policy_local1.json`. The policy can be displayed with the following command:
- command: `./origo policy-get policy_local1`
- output:
```
{
	"apis": [
		{
			"url": "https://localhost:44301/my-btc-usdt-order",
			"content-type": "application/json",
			"pattern": "\"price\":\\s*\"[0-9]+.[0-9]+\",",
			"creds": false
		}
	],
	"constraints": [
		{
			"value": "38002.1",
			"constraint": "GT"
		}
	],
	"proxies": [
		{
			"host": "localhost",
			"port": "8082",
			"mode": "signature",
			"pubKey": "3282734573475",
			"algorithm": "Ed25519"
		}
	]
}
```
The policy queries the handler of the local server and defines a greater than value comparison of the price float value. Once a developer has defined a policy, the policy can be transpiled into a snark-circuit generator script. The generator script can be created by the _ORIGO_ transpile command for the previously specified policy as follows:
- command: `./origo policy-transpile policy_local1 MyGenerator`
- output: `MyGenerator.java` file in the location `dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/MyGenerator.java` which is then compiled and the java class file is compied to the location `prover/zksnark_build/jsnark/bin/examples/generators/tranpiled/MyGenerator.class`.

In the current version of _ORIGO_, the generator script is a java program which, once compiled with the respective input data, creates the arithmetic representation of the circuit and outputs witness values. Input data for the key derivation and record data circuits is derived from tls handshake and record layer communication transcripts. This step has to be considered next such that the prover can compute the arithmetic representation of the circuit and compute the witness values. Please not that this sequence of creating the circuit and witness values exists due to the structure of Jsnark and can look different if other zk snark system implementations are used.


#### Step 2: Start Server and Proxy services
Once the policy is transpiled, the next step is to collect necessary input data such that the snark circuit can be compiled and the witness values can be created. Therefore, the server and proxy must be started as follows:
- command: `./origo server-start`
- command: `./origo proxy-start`

The command `./origo server-start` starts the server. The command `./origo server-alive` shows if the server is currently up and running by returning _true_ or _false_. The command `./origo server-config` returns the current server configuration file. Last, the command `./origo server-stop` stops the server service and should be called after the client has performed the request.
In the same way as the server can be controlled, the commands `./origo proxy-start`, `./origo proxy-alive`, `./origo proxy-config`, and `./origo proxy-stop` control the proxy service.
 

#### Step 3: Client performs TLS handshake and record query
Once the server and proxy is up and running, the prover can create a tls session and send a query according to a policy to receieve and http response. Again, in this case of the local server, there are no credentials required which is why the `local.json` credentials file without values is sufficient. The credentials filename still must be provided at this point. The commands and output coming from the prover and proxy is as follows:
- command: `./origo prover-request policy_local1 local`
- output (prover): inside the prover folder, two files will be created `prover/local_storage/PolicyExtractJson.json` and `PolicyExtractJsonShared.json`. These files extract necessary private input data necessary for circuit compilation. More detailed descriptions of all values inside these files are described in [here](../../prover/README.md).
- output (proxy): inside the proxy folder, handshake and record layer traffic is captured and categorized in traffic originating from the client and server in the files `proxy/service/local_storage/ProverSentRecords` and `proxy/service/local_storage/ServerSentRecords`, both in `.raw` and `.txt` files.


#### Step 4: Proxy post-processing of traffic transcript
Once the data has been captured, the proxy can postprocess traffic to prepare all public input required to verify the zero-knowledge proof of the prover according to a public policy. Additionally, the prover can now go ahead and compile the snark circuit. In this tutorial, we start off with the proxy preprocessing such that all data preparation is finalized and we can move to the zkp topics afterwards. To postprocess data, the proxy runs the next command:
- command: `./origo proxy-postprocess policy_local1`
- output: the public input file is created at the location `proxy/service/local_storage/PublicInput.json` and you can find a detailed description of all these values in [here](../../proxy/README.md).


#### Step 5: Stop Server and Proxy services
Once data capturing and postprocessing is completed, you can shut down the server and proxy services with the commands:
- command: `./origo server-stop`
- command: `./origo proxy-stop`


#### Step 6: Compile snark circuit with captured transcript data
Next we can generate the arithmetic circuit representation of a _ORIGO_ proof and compute witness data at the prover with the commands:
- command: `./origo prover-compile MyGenerator policy_local1`
- output: `prover/zksnark_build/jsnark/MyGenerator.arith` and `prover/zksnark_build/jsnark/MyGenerator.in` files which can be passed to the libsnark backend binaries to compute the zkp setup, proof, and verification.


#### Step 7: Perform snark setup (prover and verifier key) and generate proof
The prover afterwards proceeds by computing the actual proof as follows:
- command: `./origo prover-prove MyGenerator`
- output: the zkp `proof.raw` and the verifier key `vk.raw` which are generated at the location `prover/zksnark_build/`. These files are generated by the libsnark binary `run_generate_prove` which executes the setup and proof computation of the zero knowledge proof. Notice that the setup algorithm should be executed by a separated trusted third party and we soley execute both algorithms until now at a single party out of convenience and the fact that our implementation is a Proof of Concept.


#### Step 8: Verify proof
Once the proof has been successfully generated, the proxy as a verifier can verify the proof as follows:
- command: `./origo proxy-verify`
- output: the output should show a successfull libsnark proof verification if you managed to successfully execute all previous steps.



Congratulations, you managed to run the first complete tutorial of _ORIGO_ in the local deployment version.

To recap and see all available commands of _ORIGO_ including descriptions, just call `./origo`.

