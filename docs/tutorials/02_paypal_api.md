## Tutorial 02: Proving that your Paypal balance is above a certain threshold


#### Step 1: Inspect and refresh private API credentials
This tutorial uses _ORIGO_ to prove a value derived from the response of a real API. In this case, we make use of the Paypal sandbox environment which requires management of private credentials before the API can be queried. We keep sensitive API credentials of the prover in the `prover/credentials/paypal.json` file. The credentials file contains enpoints and private values (e.g. access\_token) required to query the paypal API. Before we can make a query to the paypal API defined in the policy `ledger_policy/policy_paypal1.json`, we must refresh all private query parameters inside the credentials file. This can be achieved as follows:
- command: `./origo prover-credentials-refresh paypal`
- output: the `AccessToken` parameter will be refreshed as well as the order identifier kept inside the `UrlPrivateParts` field.

In order to be able to refresh paypal sandbox credentials, users must first create their paypal sandbox `ClientID` and `ClientSecret`. Notice that you can work with Postman to generate these values too. We automated the step of refreshing credentials such that we can script the evaluation of multiple API requests and proofs.


#### Step 2: Policy inspection and transpilation
Next, in this tutorial, the public policy against the paypal sandbox API is of interest and can be seen as follows:
- command: `./origo policy-get policy_paypal1`
- output:
```
{
	"apis": [
		{
			"url": "https://api-m.sandbox.paypal.com/v2/checkout/orders/",
			"content-type": "application/json",
			"pattern": "\"currency_code\":\"USD\",\"value\":\"[0-9]+.[0-9]+\",",
			"creds": true
		}
	],
	"constraints": [
		{
			"value": "098.00",
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
Again, as in the first [tutorial](./01_local_api.md) of _ORIGO_, the policy can be transpiled to a circuit generator file, which is then compiled to a `.class` file and copied into the `prover/zksnark_build/jsnark/bin/examples/generators/transpiled/` location with:
- command: `./origo policy-transpile policy_paypal1 MyPayPalGenerator`
- output: `MyPayPalGenerator.java` file in the location `dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/`, which is then compiled into a java class file and copied to `prover/zksnark_build/jsnark/bin/examples/generators/tranpiled/MyPayPalGenerator.class`.


#### Step 3: Start Proxy service
Next, to collect transcript data for zkp generation and verification, we must start the proxy with the command:
- command: `./origo proxy-start`


#### Step 4: Client performs TLS handshake and record query
Once the proxy is up and running, the prover can create a tls session and send a query according to a policy to receieve and http response from the paypal API. In order to do so, the request command must specify the policy the request should be generated against and provide fresh and valid credentials. To perform the request against the paypal API and to capture traffic at the proxy, the user executes:
- command: `./origo prover-request policy_paypal1 paypal`
- output (prover): again, inside the prover folder, two files will be created `prover/local_storage/PolicyExtractJson.json` and `PolicyExtractJsonShared.json`. These files extract necessary private input data necessary for circuit compilation. More detailed descriptions of all values inside these files are described in [here](../../prover/README.md).
- output (proxy): inside the proxy folder, handshake and record layer traffic is captured and categorized in traffic originating from the client and server in the files `proxy/service/local_storage/ProverSentRecords` and `proxy/service/local_storage/ServerSentRecords`, both in `.raw` and `.txt` files.

*Please notice* that all old files from a previous _ORIGO_ exeuction will be overwritten. So please make sure to copy and backup files to a different location if you are interested in file persistence for later use.


#### Step 5: Proxy post-processing of traffic transcript
Once the data has been captured, the proxy can postprocess traffic to prepare all public input required to verify the zero-knowledge proof of the prover according to a public policy. To postprocess data, the proxy runs the next command:
- command: `./origo proxy-postprocess policy_paypal1`
- output: the public input file is created at the location `proxy/service/local_storage/PublicInput.json` and you can find a detailed description of all these values in [here](../../proxy/README.md).


#### Step 6: Stop Proxy service
Once data capturing and postprocessing is completed, you can shut down the proxy services with the commands:
- command: `./origo proxy-stop`


#### Step 7: Compile snark circuit with captured transcript data
Next, with the captured data and extracted values according to a policy, we can generate the arithmetic circuit representation of a _ORIGO_ proof and compute witness data at the prover with the commands:
- command: `./origo prover-compile MyPayPalGenerator policy_paypal1`
- output: `prover/zksnark_build/jsnark/MyPayPalGenerator.arith` and `prover/zksnark_build/jsnark/MyPayPalGenerator.in` files which can be passed to the libsnark backend binaries to compute the zkp setup, proof, and verification.


#### Step 8: Perform snark setup (prover and verifier key) and generate proof
Now you can proceed with the prover by computing the actual proof as follows:
- command: `./origo prover-prove MyPayPalGenerator`
- output: the zkp `proof.raw` and the verifier key `vk.raw` are generated at the location `prover/zksnark_build/`. These files are generated by the libsnark binary `run_generate_prove` which executes the setup and proof computation of the zero knowledge proof. *Notice* that the setup algorithm should be executed by a separated trusted third party and we soley execute both algorithms until now at a single party out of convenience and the fact that our implementation is a Proof of Concept.


#### Step 9: Verify proof
Once the proof has been successfully generated, the proxy as a verifier can verify the proof as follows:
- command: `./origo proxy-verify`
- output: the output should show a successfull libsnark proof verification if you managed to successfully execute all previous steps.



Congratulations, you managed to run the second complete tutorial of _ORIGO_ which proves a sensitive confidential value from the Paypal sandbox API environment.

To recap and see all available commands of _ORIGO_ including descriptions, just call `./origo`.

