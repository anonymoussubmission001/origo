#!/bin/bash

###### function declarations ############

cleanEvaluationLogs()
{
	# echo "I was called as : $@"
	echo "cleaning evaluation logs"
	rm -rf server/evaluation.log
	rm -rf proxy/service/evaluation.log
	rm -rf prover/tls/evaluation.log
	rm -rf commands/evaluation.log
}

cleanCapturedTraffic()
{
	echo "cleaning capture traffic data"
	rm -rf prover/local_storage/PolicyExtractJson.json
	rm -rf prover/local_storage/PolicyExtractJsonShared.json
	rm -rf proxy/service/local_storage/PublicInput.json
	rm -rf proxy/service/local_storage/ProverSentRecords.raw
	rm -rf proxy/service/local_storage/ProverSentRecords.txt
	rm -rf proxy/service/local_storage/ProverSentRecords.raw
	rm -rf proxy/service/local_storage/ProverSentRecords.txt
}

cleanSnarkFiles()
{
	echo "cleaning snark specific files"
	rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/LocalGen.java
	rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/PayPalGen.java
	rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/bin/examples/generators/transpiled/LocalGen.class
	rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/bin/examples/generators/transpiled/PayPalGen.class

	rm -rf prover/zksnark_build/jsnark/bin/examples/generators/transpiled/LocalGen.class
	rm -rf prover/zksnark_build/jsnark/bin/examples/generators/transpiled/PayPalGen.class
	rm -rf prover/zksnark_build/jsnark/LocalGen_Circuit.arith
	rm -rf prover/zksnark_build/jsnark/PayPalGen_Circuit.arith
	rm -rf prover/zksnark_build/jsnark/LocalGen_Circuit.in
	rm -rf prover/zksnark_build/jsnark/PayPalGen_Circuit.in

	rm -rf prover/zksnark_build/proof.raw
	rm -rf prover/zksnark_build/vk.raw
}

###### protocol evaluation  ############

echo "start evaluation"

# logging cleanup
cleanEvaluationLogs

###### local mode ######################

# define policies to evaluate
policyList="policy_local1 policy_local2"

# start servers

# Iterate the string variable using for loop
for val in $policyList; do

	# cleaning files
	cleanCapturedTraffic

	# clean up snark files
	cleanSnarkFiles

	# print policy name
	echo evaluate policy file: $val

	# run protocol
	./origo server-start
	./origo proxy-start

	./origo policy-transpile $val LocalGen
	./origo prover-request $val local1
	./origo proxy-postprocess $val

	./origo server-stop
	./origo proxy-stop

	./origo prover-compile LocalGen $val
	./origo prover-prove LocalGen
	./origo proxy-verify
done

###### paypal api mode ######################

# define policies to evaluate
policyList2="policy_paypal1 policy_paypal2"

for val in $policyList2; do

	# cleaning files
	cleanCapturedTraffic

	# clean up snark files
	cleanSnarkFiles

	# print policy name
	echo evaluate policy file: $val

	# run protocol
	./origo proxy-start

	./origo policy-transpile $val PayPalGen
	./origo prover-credentials-refresh paypal
	./origo prover-request $val paypal
	./origo proxy-postprocess $val

	./origo proxy-stop

	./origo prover-compile PayPalGen $val
	./origo prover-prove PayPalGen
	./origo proxy-verify
done

echo "evaluation done"


