## _ORIGO_ Evaluation

### Reproducing Values of the Research Paper
To reproduce results presented in the research paper, you have to correctly install _ORIGO_ as described in the [installation](./00_installation.md) documentation. Next, you have to execute `./evaluation.sh` from the root location of the repository. The evaluation executes _ORIGO_ in local deployment mode, where we use three different policies with different constraints (`GT`, `LT`, `EQ`) and values. Next, the evaluation executes different policies targeting the Paypal API with different constraints (`GT`, `LT`, `EQ`) and values. All timing values are stored in the following locations in files called `evaluation.log`, which we remove before every execution of the evaluation.
```
rm -rf server/evaluation.log
rm -rf proxy/service/evaluation.log
rm -rf prover/tls/evaluation.log
rm -rf commands/evaluation.log
```
We executed the `./evaluation` script 10 times and averaged the numbers to compensate deviations among numbers. This means, the numbers you get when running the evaluation script once should be in close range to our evaluation results if you execute the repository on a machine with the same specs as described in the _ORIGO_ research paper.

*Notice*, we remove cature files between individual protocol executions and clean up all `evaluation.log` files when starting a new evaluation. We also clean up transpiled `.java` generator files, compiled java `.class` files, `.artih` and `.in` files of compiled circuits and we remove the `proof.raw` and `vk.raw` files when starting an evaluation. After an evaluation has been conducted, we keep all created files further available for inspection. The commands of other files we remove before and during the execution of an evaluation run are listed below.

#### removing files with captured data
```
rm -rf prover/local_storage/PolicyExtractJson.json
rm -rf prover/local_storage/PolicyExtractJsonShared.json
rm -rf proxy/service/local_storage/PublicInput.json
rm -rf proxy/service/local_storage/ProverSentRecords.raw
rm -rf proxy/service/local_storage/ProverSentRecords.txt
rm -rf proxy/service/local_storage/ProverSentRecords.raw
rm -rf proxy/service/local_storage/ProverSentRecords.txt
```

#### clean up of snark specific files
```
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
```

