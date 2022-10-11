package examples.gadgets.aes_gcm;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.helpers.GetIVGadget;

public class DynamicAESGCMGadget extends Gadget {
    private Wire[] nonce;
    private Wire[] key;

    private Wire[] plaintext;
    private Wire[] ciphertext;

    int startBlockIdx;

    public DynamicAESGCMGadget(Wire[] key, Wire[] nonce, Wire[] plaintext,
                               int startBlockIdx, String... desc) {
        super(desc);
        this.nonce = nonce;
        this.key = key;
        this.startBlockIdx = startBlockIdx;
        this.plaintext = plaintext;
        buildCircuit();
    }

    private void buildCircuit() {
        int count = plaintext.length/16;
        Wire[] tmpCipher;
        Wire[] chunk = new Wire[16];
        ciphertext = new Wire[plaintext.length];
        for (int i = 0; i < count; i++) {
            System.arraycopy(plaintext, 16*i, chunk,0, 16);
            Wire[] iv = new GetIVGadget(nonce, i+startBlockIdx+2).getOutputWires();
            tmpCipher = new AES128WrapperGadget(iv, key).getOutputWires();
            chunk = new Xor16Gadget(tmpCipher, chunk).getOutputWires();
            System.arraycopy(chunk, 0, ciphertext , i * 16, 16);
        }
    }

    @Override
    public Wire[] getOutputWires() {
        return ciphertext;
    }
}
