package examples.tests.aes_gcm;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.aes_gcm.DynamicAESGCMGadget;
import junit.framework.TestCase;
import org.junit.Test;
import util.Util;

public class DynamicAESGCM_Test extends TestCase{
    @Test
    public void testCase1() {
        String keyStr = "fe47fcce5fc32665d2ae399e4eec72ba";
        String nonceStr = "5adb9609dbaeb58cbd6e7275";
        String plaintextStr = "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429";
        String expectCiphertextStr = "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269";
        CircuitGenerator generator = new CircuitGenerator("DynamicAESGCM_test1") {
            Wire[] plaintextWires;
            Wire[] keyWires;
            Wire[] nonceWires;

            @Override
            protected void buildCircuit() {
                plaintextWires = createInputWireArray(plaintextStr.length()/2);
                keyWires = createProverWitnessWireArray(keyStr.length()/2);
                nonceWires = createProverWitnessWireArray(nonceStr.length()/2);
                Wire[] output = new DynamicAESGCMGadget(keyWires,nonceWires, plaintextWires, 0).getOutputWires();
                makeOutputArray(output);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

                for (int i = 0; i < plaintextStr.length()/2; i++) {
                    evaluator.setWireValue(plaintextWires[i], Integer.valueOf(plaintextStr.substring(i*2, i*2+2), 16) );
                }
                for (int i = 0; i < keyStr.length()/2; i++) {
                    //evaluator.setWireValue(keyWires[i], keyStr.charAt(i));
                    evaluator.setWireValue(keyWires[i], Integer.valueOf(keyStr.substring(i*2, i*2+2), 16));
                }
                for (int i = 0; i < nonceStr.length()/2; i++) {
                    evaluator.setWireValue(nonceWires[i], Integer.valueOf(nonceStr.substring(i*2, i*2+2), 16) );
                }

            }
        };


        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }

        assertEquals(outDigest, expectCiphertextStr);
    }


    @Test
    public void testCase2() {
        String keyStr = "ae99ba0380e3fffdf221fc4587e1ef4a";
        String nonceStr = "81e2638f519fc55b3fecfe0f";
        String plaintextStr = "43222c0a202020202020202022382e20426964205072696365223a202232313735392e3939303030303030222c0a2020";
        String expectCiphertextStr = "22b0c07892c89150cc2eb317bbf3a742c2abbc901fbcea091bd65de776bd0f297ffb9f94971f1ccc6807a7299def0936";

        CircuitGenerator generator = new CircuitGenerator("DynamicAESGCM_test2") {
            Wire[] plaintextWires;
            Wire[] keyWires;
            Wire[] nonceWires;

            @Override
            protected void buildCircuit() {
                plaintextWires = createInputWireArray(plaintextStr.length()/2);
                keyWires = createProverWitnessWireArray(keyStr.length()/2);
                nonceWires = createProverWitnessWireArray(nonceStr.length()/2);
                Wire[] output = new DynamicAESGCMGadget(keyWires,nonceWires, plaintextWires, 47).getOutputWires();
                makeOutputArray(output);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

                for (int i = 0; i < plaintextStr.length()/2; i++) {
                    evaluator.setWireValue(plaintextWires[i], Integer.valueOf(plaintextStr.substring(i*2, i*2+2), 16) );
                }
                for (int i = 0; i < keyStr.length()/2; i++) {
                    //evaluator.setWireValue(keyWires[i], keyStr.charAt(i));
                    evaluator.setWireValue(keyWires[i], Integer.valueOf(keyStr.substring(i*2, i*2+2), 16));
                }
                for (int i = 0; i < nonceStr.length()/2; i++) {
                    evaluator.setWireValue(nonceWires[i], Integer.valueOf(nonceStr.substring(i*2, i*2+2), 16) );
                }

            }
        };


        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }

        assertEquals(outDigest, expectCiphertextStr);
    }


    @Test
    public void testCase3() {
        String keyStr = "3c8598a08e9d98237498c84dd64d2ffd";
        String nonceStr = "794ba51b4ce10d1242cee68b";
        String plaintextStr = "20202022323032322d30372d30372031353a31383a3030223a207b0a20202020202020202020202022312e206f70656e223a20223134312e31383030222c0a20";
        String expectCiphertextStr = "e299486297f0c3a99796fbae87eb1cda0d867b9ed7eff0505fb2cb9dd915954f1a0a325a6b334aa9b44c05e430bb51e0470a8a0e9370e7d81319ee488f6b8108";

        CircuitGenerator generator = new CircuitGenerator("DynamicAESGCM_test2") {
            Wire[] plaintextWires;
            Wire[] keyWires;
            Wire[] nonceWires;

            @Override
            protected void buildCircuit() {
                plaintextWires = createInputWireArray(plaintextStr.length()/2);
                keyWires = createProverWitnessWireArray(keyStr.length()/2);
                nonceWires = createProverWitnessWireArray(nonceStr.length()/2);
                Wire[] output = new DynamicAESGCMGadget(keyWires,nonceWires, plaintextWires, 55).getOutputWires();
                makeOutputArray(output);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

                for (int i = 0; i < plaintextStr.length()/2; i++) {
                    evaluator.setWireValue(plaintextWires[i], Integer.valueOf(plaintextStr.substring(i*2, i*2+2), 16) );
                }
                for (int i = 0; i < keyStr.length()/2; i++) {
                    //evaluator.setWireValue(keyWires[i], keyStr.charAt(i));
                    evaluator.setWireValue(keyWires[i], Integer.valueOf(keyStr.substring(i*2, i*2+2), 16));
                }
                for (int i = 0; i < nonceStr.length()/2; i++) {
                    evaluator.setWireValue(nonceWires[i], Integer.valueOf(nonceStr.substring(i*2, i*2+2), 16) );
                }

            }
        };


        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }

        assertEquals(outDigest, expectCiphertextStr);
    }


}
