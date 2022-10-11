package examples.gadgets.helpers;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;

public class GetIVGadget extends Gadget {

	private Wire[] iv;
	private int counter;
	private Wire[] output;

	// returns concatenation of iv || counter,
	// where counter is 4 byte Uint in big endian order
	public GetIVGadget(Wire[] iv, int counter, String... desc) {
		super(desc);
		// if (a.length != b.length) {
		// 	throw new IllegalArgumentException();
		// }
		this.iv = iv;
		this.counter = counter;
		buildCircuit();
	}

	private void buildCircuit() {
		// public byte[] toByteArray():
		// Returns a byte array containing the two's-complement representation of this BigInteger. The byte array will be in big-endian byte-order: the most significant byte is in the zeroth element. The array will contain the minimum number of bytes required to represent this BigInteger, including at least one sign bit, which is (ceil((this.bitLength() + 1)/8)). (This representation is compatible with the (byte[]) constructor.)

		// copy nonce into first 12 bytes
		// Wire[] output = generator.generateZeroWireArray(16);
		output = new Wire[16];
		byte[] tmp_array = BigInteger.valueOf(counter).toByteArray();
		for (int i = 0; i < 12; i++) {
     			output[i] = iv[i];
		}
		// zero padding bytes to wire
		int num_padding = 4-tmp_array.length;
		for (int i=0; i < num_padding; i++) {
			output[12+i] = generator.getZeroWire();
		}
		// insert counter into wire bytes
		for (int i=0; i < tmp_array.length; i++) {
			// fill in from back
			output[12+num_padding+i] = generator.createConstantWire((tmp_array[i] + 256) % 256);
			//Wire generator.createConstantWire(BigInteger.valueOf(this.counter), 32);
			//output[15-i] = tmp_array[i];
		}

		
		//BigInteger bigIntegerCounter = BigInteger.valueOf(counter);
		//Wire[] output = generator.generateZeroWireArray(16);
		// output = generator.getZeroWire();
		// for (int i = 0; i < a.length; i++) {
		//Wire product = a.mul(b, "Multiply elements # a times b");
		//output = output.add(product);
		//}
	}

	@Override
	public Wire[] getOutputWires() {
		//Wire[] result = new Wire[]{ output };
		return output;
	}
}
