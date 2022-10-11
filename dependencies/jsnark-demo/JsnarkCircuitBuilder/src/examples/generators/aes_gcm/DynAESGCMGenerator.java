package examples.generators.aes_gcm;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.helpers.GetIVGadget;
import examples.gadgets.aes_gcm.AES128WrapperGadget;
import examples.gadgets.aes_gcm.Xor16Gadget;

// A sample usage of the AES128 CBC gadget
public class DynAESGCMGenerator  extends CircuitGenerator {

	private Wire[] plaintext;
	private Wire[] key;
	private Wire[] iv;
	private Wire[] intermediate;
	private Wire[] ciphertext;

	public DynAESGCMGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {

		key = createProverWitnessWireArray(16);
		iv = createInputWireArray(12);
		plaintext = createProverWitnessWireArray(16);

		Wire[] iv_counter = new GetIVGadget(iv, 2).getOutputWires();
		intermediate = new AES128WrapperGadget(iv_counter, key).getOutputWires();
		ciphertext = new Xor16Gadget(intermediate, plaintext).getOutputWires();
		makeOutputArray(ciphertext);
		for (Wire c : ciphertext) {
			makeOutput(c);
		}

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

		String keyHexStr = "7fddb57453c241d03efbed3ac44e371c";
		// String ivctrHexStr = "ee283a3fc75575e33efd488700000002";
		String nonce = "ee283a3fc75575e33efd4887";
		// expected intermediary output after aes128: "f913e6112038d53b4fdb97261a1a0b5f";
		String plaintextHexStr = "d5de42b461646c255c87bd2962d3b9a2";
		// expected output: "2ccda4a5415cb91e135c2a0f78c9b2fd";

		for (int i = 0; i < key.length; i++) {
		    circuitEvaluator.setWireValue(key[i], Integer.valueOf(keyHexStr.substring(i*2,i*2+2), 16));
		}
		for (int i = 0; i < iv.length; i++) {
		    circuitEvaluator.setWireValue(iv[i], Integer.valueOf(nonce.substring(i*2,i*2+2), 16));
		}

		for (int i = 0; i < plaintext.length; i++ ) {
		    circuitEvaluator.setWireValue(plaintext[i], Integer.valueOf(plaintextHexStr.substring(i*2,i*2+2), 16));
		}
	}

	public static void main(String[] args) throws Exception {

		Config.hexOutputEnabled = true;
		DynAESGCMGenerator generator = new DynAESGCMGenerator(
			"DynAESGCMGenerator_Circuit");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();

	}
}

