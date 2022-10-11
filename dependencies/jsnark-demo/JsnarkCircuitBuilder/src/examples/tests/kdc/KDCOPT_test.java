package examples.tests.kdc;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.comparator.JSONKeyValuePairComparatorGadget;
import examples.gadgets.kdc.KDCOPTGadget;
import examples.gadgets.kdc.KDCOPTOuterHMACGadget;
import junit.framework.TestCase;
import org.junit.Test;
import util.Util;

import java.util.Arrays;

public class KDCOPT_test extends TestCase {

    @Test
    public void testCase1(){
        CircuitGenerator generator = new CircuitGenerator("Test1_KDCOPT_OuterHMAC") {

            private Wire[] HS;
            private Wire[] innerHash;
            private Wire[] output;
            @Override
            protected void buildCircuit() {
                innerHash = createInputWireArray(32);
                HS = createProverWitnessWireArray(32);
                Wire[] output = new KDCOPTOuterHMACGadget(HS,innerHash).getOutputWires();
                makeOutputArray(output);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

                String HSStr = "5ac934538933f93a0bf6050f63befb268c52a7b2d3efc6cf0629b139509b11d3";
                String innerHashStr = "6738846eba35530374b8e66b708f7deb4af2dd91f1e25911b0aaad93d01bc126";
                String expectOutput = "8eb2b38d5c954863181e5be960def4b338e813fc12cd951417799f4d36e024fe";

                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(innerHash[i], Integer.valueOf(innerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(HS[i], Integer.valueOf(HSStr.substring(i*2,i*2+2), 16));
                }
            }};

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        String expectedDigest = "8eb2b38d5c954863181e5be960def4b338e813fc12cd951417799f4d36e024fe";
            for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigest);
    }


    @Test
    public void testCase2(){
        CircuitGenerator generator = new CircuitGenerator("Test1_KDCOPT_2") {

            private Wire[] HS;
            private Wire[] SHTSInnerHashOutput;
            private Wire[] output;
            //    private Wire[] SHTS;
            private Wire[] kfsInnerHashOutput;
            private Wire[] sfInnerHashOutput;
            private Wire[] dHSInnerHashOutput;
            private Wire[] MSInnerHashOutput;
            private Wire[] SATSInnerHashOutput;
            private Wire[] CATSInnerHashOutput;
            private Wire[] kSAPPKeyInnerHashOutput;
            private Wire[] kSAPPIVInnerHashOutput;
            private Wire[] kCAPPKeyInnerHashOutput;
            private Wire[] kCAPPIVInnerHashOutput;

            @Override
            protected void buildCircuit() {
                HS = createProverWitnessWireArray(32);
                SHTSInnerHashOutput = createInputWireArray(32);
                kfsInnerHashOutput = createInputWireArray(32);
                sfInnerHashOutput = createInputWireArray(32);
                dHSInnerHashOutput = createInputWireArray(32);
                MSInnerHashOutput = createInputWireArray(32);
                SATSInnerHashOutput = createInputWireArray(32);
                CATSInnerHashOutput = createInputWireArray(32);
                kSAPPKeyInnerHashOutput = createInputWireArray(32);
                kSAPPIVInnerHashOutput = createInputWireArray(32);
                kCAPPKeyInnerHashOutput = createInputWireArray(32);
                kCAPPIVInnerHashOutput = createInputWireArray(32);

                Wire[] SHTS = new KDCOPTOuterHMACGadget(HS,SHTSInnerHashOutput).getOutputWires();
                Wire[] SHTSByteFormat = formatOutput(SHTS);
                Wire[] kfs = new KDCOPTOuterHMACGadget(SHTSByteFormat,kfsInnerHashOutput).getOutputWires();
                Wire[] kfsByteFormat = formatOutput(kfs);
                Wire[] SF = new KDCOPTOuterHMACGadget(kfsByteFormat, sfInnerHashOutput).getOutputWires();
                Wire[] SFByteFormat = formatOutput(SF);
                Wire[] dHS = new KDCOPTOuterHMACGadget(HS, dHSInnerHashOutput).getOutputWires();
                Wire[] dHSByteFormat = formatOutput(dHS);
                Wire[]  MS = new KDCOPTOuterHMACGadget(dHSByteFormat, MSInnerHashOutput).getOutputWires();
                Wire[] MSByteFormat = formatOutput(MS);
                Wire[]  SATS = new KDCOPTOuterHMACGadget(MSByteFormat, SATSInnerHashOutput).getOutputWires();
                Wire[] SATSByteFormat = formatOutput(SATS);
                Wire[]  kSAPPKey = new KDCOPTOuterHMACGadget(SATSByteFormat, kSAPPKeyInnerHashOutput).getOutputWires();
                Wire[]  kSAPPIV = new KDCOPTOuterHMACGadget(SATSByteFormat, kSAPPIVInnerHashOutput).getOutputWires();

                Wire[]  CATS = new KDCOPTOuterHMACGadget(MSByteFormat, CATSInnerHashOutput).getOutputWires();
                Wire[] CATSByteFormat = formatOutput(CATS);
                Wire[]  kCAPPKey = new KDCOPTOuterHMACGadget(CATSByteFormat, kCAPPKeyInnerHashOutput).getOutputWires();
                Wire[]  kCAPPIV = new KDCOPTOuterHMACGadget(CATSByteFormat, kCAPPIVInnerHashOutput).getOutputWires();

                Wire[] kSAPPKeyByteFormat = formatOutput(kSAPPKey);
                kSAPPKeyByteFormat = truncate(kSAPPKeyByteFormat, 16);
                Wire[] kSAPPIVByteFormat = formatOutput(kSAPPIV);
                kSAPPIVByteFormat = truncate(kSAPPIVByteFormat, 12);

                Wire[] kCAPPKeyByteFormat = formatOutput(kCAPPKey);
                kCAPPKeyByteFormat = truncate(kCAPPKeyByteFormat, 16);
                Wire[] kCAPPIVByteFormat = formatOutput(kCAPPIV);
                kCAPPIVByteFormat = truncate(kCAPPIVByteFormat, 12);
                output = kCAPPIVByteFormat;
                makeOutputArray(output, "digest");

            }

            @Override
            public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

                String HSStr = "45073a01656ca5d43508352f349088e8ff25ff1a1ec8cc3f30cef832b2dd9add";
                String SHTSInnerHashStr = "3a6857cf5e19272770bad5748b7ec784e835bfae17d49c599fe35f041fe31faa";
                String kfsInnerHashStr = "afa7a9a1a5c5641e038a15cbb549ad15ddd944b565e19ab70181764aecaa1943";
                String sfInnerHashStr = "435e4481302875e9be0aeff45663fee79c8dc7f3ace7bbddc63c84d9ea01ebb3";
                String dHSInnerHashStr = "a1357b0f1a2f28bf8015192584d9080bbb85a38f4b39080215400eebc18f7f26";
                String MSHSInnerHashStr = "58aa7a0017bec7140e087b191a1f04904461fba1d54b3020f656c08528446efb";
                String SATSInnerHashStr = "bb2d4af0845e2d9489994cde6fb7c5136dbb99b90f92d1e53ba3107a2e3c7441";
                String CATSInnerHashStr = "3a36015550a9b290602c7ba0b403cc28a98f86ef98df5a25075be2b42ed1484b";
                String kSAPPKeyInnerHashStr = "81430ab6b79ca1467a08636ced56bbec47b02b2167eae925321985475b94521b";
                String kSAPPIVInnerHashStr = "c0f1212dff7aefbeb22dad57b288d90b675d259ddb42926fa2079f027ea8ba15";
                String kCAPPKeyInnerHashStr = "51cfb34a313c8bef045f8638fc7e8469fd4bbb3a56e101d0f2d9000e9a3c0f81";
                String kCAPPIVInnerHashStr = "a23281ccbc0ec51126df58dade03e8d9f8be3c072f3a80926fe0b95e2bd1a19c";


                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(HS[i], Integer.valueOf(HSStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(SHTSInnerHashOutput[i], Integer.valueOf(SHTSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kfsInnerHashOutput[i], Integer.valueOf(kfsInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(sfInnerHashOutput[i], Integer.valueOf(sfInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(dHSInnerHashOutput[i], Integer.valueOf(dHSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(MSInnerHashOutput[i], Integer.valueOf(MSHSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(SATSInnerHashOutput[i], Integer.valueOf(SATSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(CATSInnerHashOutput[i], Integer.valueOf(CATSInnerHashStr.substring(i*2,i*2+2), 16));
                }

                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kSAPPKeyInnerHashOutput[i], Integer.valueOf(kSAPPKeyInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kSAPPIVInnerHashOutput[i], Integer.valueOf(kSAPPIVInnerHashStr.substring(i*2,i*2+2), 16));
                }

                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kCAPPKeyInnerHashOutput[i], Integer.valueOf(kCAPPKeyInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kCAPPIVInnerHashOutput[i], Integer.valueOf(kCAPPIVInnerHashStr.substring(i*2,i*2+2), 16));
                }
            }

            private Wire[] formatOutput(Wire[] Bits32Wire) {
                Wire[] Bits8Wire = new Wire[Bits32Wire.length*4];
                Wire[] WireBits = new WireArray(Bits32Wire).getBits(32).asArray();
                Wire[] tmp;
                int idx = 0;
                for (int i = 0; i < 32; i++) {
                    if (i % 4 == 0) {
                        tmp = Arrays.copyOfRange(WireBits, i * 8+3*8,(i + 1) * 8+3*8);
                    }
                    else if (i % 4 == 1) {
                        tmp = Arrays.copyOfRange(WireBits, i * 8+1*8,(i + 1) * 8+1*8);
                    }
                    else if (i % 4 == 2) {
                        tmp = Arrays.copyOfRange(WireBits, i * 8-8,(i + 1) * 8-8);
                    }
                    else  {
                        tmp = Arrays.copyOfRange(WireBits, i * 8-3*8,(i + 1) * 8-3*8);
                    }
                    Bits8Wire[idx++] = new WireArray(tmp).packAsBits(8);
                }
                return Bits8Wire;
            }
            private Wire[] truncate(Wire[] wires, int length) {
                Wire[] truncatedWires = new Wire[length];
                System.arraycopy(wires, 0, truncatedWires, 0, length);
                return truncatedWires;
            }
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        String expectedDigest = "2c6069cd44a3bb25a9b872bc";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigest);
    }


    @Test
    public void testCase3(){
        CircuitGenerator generator = new CircuitGenerator("Test1_KDCOPT_3") {

            private Wire[] output;
            private Wire[] HS;
            private Wire[] SHTSInnerHashOutput;

            private Wire[] kfsInnerHashOutput;
            private Wire[] sfInnerHashOutput;
            private Wire[] dHSInnerHashOutput;
            private Wire[] MSInnerHashOutput;
            private Wire[] SATSInnerHashOutput;
            private Wire[] CATSInnerHashOutput;
            private Wire[] kSAPPKeyInnerHashOutput;
            private Wire[] kSAPPIVInnerHashOutput;
            private Wire[] kCAPPKeyInnerHashOutput;
            private Wire[] kCAPPIVInnerHashOutput;

            private Wire[] plaintextChunks;
            private Wire[] ciphertextChunks;

            private Wire[] circuitInputSF;
            private Wire[] seqCounter;

            @Override
            protected void buildCircuit() {
                int startBlockIdx = 30;
                int blockNr = 2;
                HS = createProverWitnessWireArray(32);
                SHTSInnerHashOutput = createInputWireArray(32);
                kfsInnerHashOutput = createInputWireArray(32);
                sfInnerHashOutput = createInputWireArray(32);
                dHSInnerHashOutput = createInputWireArray(32);
                MSInnerHashOutput = createInputWireArray(32);
                SATSInnerHashOutput = createInputWireArray(32);
                CATSInnerHashOutput = createInputWireArray(32);
                kSAPPKeyInnerHashOutput = createInputWireArray(32);
                kSAPPIVInnerHashOutput = createInputWireArray(32);
                kCAPPKeyInnerHashOutput = createInputWireArray(32);
                kCAPPIVInnerHashOutput = createInputWireArray(32);
                plaintextChunks = createProverWitnessWireArray(16*blockNr);

                circuitInputSF = createProverWitnessWireArray(32);
                ciphertextChunks = createInputWireArray(16*blockNr);
                seqCounter = createInputWireArray(8);

                output = new KDCOPTGadget(HS, SHTSInnerHashOutput,  kfsInnerHashOutput, sfInnerHashOutput,
                        dHSInnerHashOutput, MSInnerHashOutput, SATSInnerHashOutput,
                        CATSInnerHashOutput, kSAPPKeyInnerHashOutput, kSAPPIVInnerHashOutput,
                        kCAPPKeyInnerHashOutput, kCAPPIVInnerHashOutput, plaintextChunks,
                       ciphertextChunks, circuitInputSF, seqCounter, startBlockIdx).getOutputWires();

                makeOutputArray(output, "digest");

            }

            @Override
            public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
                String HSStr = "04a58170602e72a980824fdc60865faf325e1a894b9c723cc5a423752996e0f6";
                String SHTSInnerHashStr = "112b5850acb7fd75fe8f4092c356b569b8f02907eaebee4c0b0dc03886ac92f0";
                String kfsInnerHashStr = "6383680126cb49d4ca6c8d92ec7aac8730c40435a44b324a3a7e2674ee76a61d";
                String sfInnerHashStr = "4c077f3f34e1d3fb5238fb0e198f52b228f941be1efdbe787cdf665799dee674";
                String dHSInnerHashStr = "48911e8a5b54e0185de7f933f8ee185632cde9fd88531183ec380cb43b7c1198";
                String MSHSInnerHashStr = "76c9bf8620d4e3faa1ace4bda0a233f0e4c993c1fd8c474e3c987976ef35eb46";
                String SATSInnerHashStr = "164c587e1fab57439a068e264ad2c80577ba34a611801991b72b3cd589ca3e0e";
                String CATSInnerHashStr = "a17cb4914037982799c110e2617dd9a7f0687ee094efb9be7da668c021a1f1f2";
                String kSAPPKeyInnerHashStr = "26f26a24462563ab93d62f4ffbf23789dc1f3412633b8bbf8c1509c04b162358";
                String kSAPPIVInnerHashStr = "aef0e12dd3579fa59c82ba2921723281e13a0343a55886dd141193183b1491d4";
                String kCAPPKeyInnerHashStr = "2e651e2f16feadf0b5e55345a652353420cec11b87052bd9d81542a905fa5135";
                String kCAPPIVInnerHashStr = "acc8cfdf651b58d2b97f738e284f0369ebb13ddbe4531783dda170abf07d62ca";
                String plaintextStr = "302c353631204575726f227d2c227072696365223a2233383030322e32222c22";
                String SFStr = "4294b43a9f2579c43b951a65ae57431804be96c9c71613ea5eeebfc83a91fbf5";
                String SeqCounterStr = "0000000000000000";
                String ciphertextStr = "74ddda545b8233a6f41fb7fc70669c30249282ca8271a47e7f57c860943caac9";

                setWires(HS, HSStr, circuitEvaluator);
                setWires(SHTSInnerHashOutput, SHTSInnerHashStr, circuitEvaluator);
                setWires(kfsInnerHashOutput, kfsInnerHashStr, circuitEvaluator);
                setWires(sfInnerHashOutput, sfInnerHashStr, circuitEvaluator);
                setWires(dHSInnerHashOutput, dHSInnerHashStr, circuitEvaluator);
                setWires(MSInnerHashOutput, MSHSInnerHashStr, circuitEvaluator);
                setWires(SATSInnerHashOutput, SATSInnerHashStr, circuitEvaluator);
                setWires(CATSInnerHashOutput, CATSInnerHashStr, circuitEvaluator);
                setWires(kSAPPKeyInnerHashOutput, kSAPPKeyInnerHashStr, circuitEvaluator);
                setWires(kSAPPIVInnerHashOutput, kSAPPIVInnerHashStr, circuitEvaluator);
                setWires(kCAPPKeyInnerHashOutput, kCAPPKeyInnerHashStr, circuitEvaluator);
                setWires(kCAPPIVInnerHashOutput, kCAPPIVInnerHashStr, circuitEvaluator);
                setWires(plaintextChunks, plaintextStr, circuitEvaluator);
                setWires(circuitInputSF, SFStr, circuitEvaluator);
                setWires(seqCounter, SeqCounterStr, circuitEvaluator);
                setWires(ciphertextChunks, ciphertextStr, circuitEvaluator);
            }
            private void setWires(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    circuitEvaluator.setWireValue(wires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2), 16));
                }
            }

        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        String expectedDigest = "01";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigest);
    }


    public void testCase4(){
        CircuitGenerator generator = new CircuitGenerator("Test1_KDCOPT_4") {

            private Wire[] output;
            private Wire[] HS;
            private Wire[] SHTSInnerHashOutput;

            private Wire[] kfsInnerHashOutput;
            private Wire[] sfInnerHashOutput;
            private Wire[] dHSInnerHashOutput;
            private Wire[] MSInnerHashOutput;
            private Wire[] SATSInnerHashOutput;
            private Wire[] CATSInnerHashOutput;
            private Wire[] kSAPPKeyInnerHashOutput;
            private Wire[] kSAPPIVInnerHashOutput;
            private Wire[] kCAPPKeyInnerHashOutput;
            private Wire[] kCAPPIVInnerHashOutput;

            private Wire[] plaintextChunks;
            private Wire[] ciphertextChunks;

            private Wire[] circuitInputSF;
            private Wire[] seqCounter;

            @Override
            protected void buildCircuit() {
                int startBlockIdx = 4;
                int blockNr = 4;
                HS = createProverWitnessWireArray(32);
                SHTSInnerHashOutput = createInputWireArray(32);
                kfsInnerHashOutput = createInputWireArray(32);
                sfInnerHashOutput = createInputWireArray(32);
                dHSInnerHashOutput = createInputWireArray(32);
                MSInnerHashOutput = createInputWireArray(32);
                SATSInnerHashOutput = createInputWireArray(32);
                CATSInnerHashOutput = createInputWireArray(32);
                kSAPPKeyInnerHashOutput = createInputWireArray(32);
                kSAPPIVInnerHashOutput = createInputWireArray(32);
                kCAPPKeyInnerHashOutput = createInputWireArray(32);
                kCAPPIVInnerHashOutput = createInputWireArray(32);
                plaintextChunks = createProverWitnessWireArray(16*blockNr);

                circuitInputSF = createProverWitnessWireArray(32);
                ciphertextChunks = createInputWireArray(16*blockNr);
                seqCounter = createInputWireArray(8);

                output = new KDCOPTGadget(HS, SHTSInnerHashOutput,  kfsInnerHashOutput, sfInnerHashOutput,
                        dHSInnerHashOutput, MSInnerHashOutput, SATSInnerHashOutput,
                        CATSInnerHashOutput, kSAPPKeyInnerHashOutput, kSAPPIVInnerHashOutput,
                        kCAPPKeyInnerHashOutput, kCAPPIVInnerHashOutput, plaintextChunks,
                        ciphertextChunks, circuitInputSF, seqCounter, startBlockIdx).getOutputWires();


                int keyValuePairLen = 59;
                int offsetKeyValuePair = 0;
               int offsetValue = 49;
                int floatStringLen = 8;
                int dotIdx = 3;
                String keyValueStartPattern = "\"2022-07-08 14:55:00\": {\n            \"1. open\": \"";
                Wire[] keyValuePair = new Wire[keyValuePairLen];
                System.arraycopy(plaintextChunks, offsetKeyValuePair, keyValuePair,0,keyValuePair.length);
                String jsonKeyStr = convertASCIIStringToHexString(keyValueStartPattern);
                output = new JSONKeyValuePairComparatorGadget(plaintextChunks, plaintextChunks.length, keyValuePair, offsetKeyValuePair,
                        keyValuePairLen, jsonKeyStr).getOutputWires();


                makeOutputArray(output, "digest");

            }

            @Override
            public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
                String HSStr = "e9b1d92d1935f26a40d452ab0fd604881641ee97e142a82c5a434af04fb78c44";
                String SHTSInnerHashStr = "499979f088b74f1055eed455f1d764590f0815ba2dc2b4fe009198223c012873";
                String kfsInnerHashStr = "75295d4574e3c6b25766c693aa05b19c1ff5146d39e4abca35b77937f50b6e2f";
                String sfInnerHashStr = "fc890bba1c455bbcab4e120b10cce69858e70565f7a3ae8c0553de9fd8c1187d";
                String dHSInnerHashStr = "6d7d503805f5e0d9076cf4ecd57f00833da01b11d5798aaea131886fb2ed5fef";
                String MSHSInnerHashStr = "4beff4e1f5b32c576642950a4426c84e31a7e76b442efd34839f1f6ecccaf05a";
                String SATSInnerHashStr = "d14d6dd0c0a774ba5b807f8fccab48f076708e8c59abfaf76cc5215fb18a5863";
                String CATSInnerHashStr = "9497b322fc7b44cf428b5aa230a5441dc7b0ff1dfa234b728f7a686b3777c5c7";
                String kSAPPKeyInnerHashStr = "63c0311991de9a6e1c4a07aeb4cc3bbe4f3ea950eb19904f947e58c9457710f4";
                String kSAPPIVInnerHashStr = "96045f763d4bb52e0a7fb070f0e5490ecf61cff25283b6594b24c875ab951100";
                String kCAPPKeyInnerHashStr = "b39afe3258e35f68bbf1de379b78db390d5f761fae3030f92457515c5edbfe14";
                String kCAPPIVInnerHashStr = "a75fcb710c29ee7c8bef8e538838b7327423f6d839778a748b4f8c710a020a47";
                String plaintextStr = "22323032322d30372d30382031343a35353a3030223a207b0a20202020202020202020202022312e206f70656e223a20223134302e37393030222c0a20202020";
                String SFStr = "f7deb8fb4674964bc55e769de43b2d53bf1c8a27274445c241d017752f80cada";
                String SeqCounterStr = "000000000000000e";
                String ciphertextStr = "604ee028a674c4f56b1b53f1849b91f32209075617af63ac849d5cbd167564ddfdcb0272c68b19e7f48a0bce6a3da430384f3f7812646678e0996c600738bb90";

                setWires(HS, HSStr, circuitEvaluator);
                setWires(SHTSInnerHashOutput, SHTSInnerHashStr, circuitEvaluator);
                setWires(kfsInnerHashOutput, kfsInnerHashStr, circuitEvaluator);
                setWires(sfInnerHashOutput, sfInnerHashStr, circuitEvaluator);
                setWires(dHSInnerHashOutput, dHSInnerHashStr, circuitEvaluator);
                setWires(MSInnerHashOutput, MSHSInnerHashStr, circuitEvaluator);
                setWires(SATSInnerHashOutput, SATSInnerHashStr, circuitEvaluator);
                setWires(CATSInnerHashOutput, CATSInnerHashStr, circuitEvaluator);
                setWires(kSAPPKeyInnerHashOutput, kSAPPKeyInnerHashStr, circuitEvaluator);
                setWires(kSAPPIVInnerHashOutput, kSAPPIVInnerHashStr, circuitEvaluator);
                setWires(kCAPPKeyInnerHashOutput, kCAPPKeyInnerHashStr, circuitEvaluator);
                setWires(kCAPPIVInnerHashOutput, kCAPPIVInnerHashStr, circuitEvaluator);
                setWires(plaintextChunks, plaintextStr, circuitEvaluator);
                setWires(circuitInputSF, SFStr, circuitEvaluator);
                setWires(seqCounter, SeqCounterStr, circuitEvaluator);
                setWires(ciphertextChunks, ciphertextStr, circuitEvaluator);
            }
            private void setWires(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    circuitEvaluator.setWireValue(wires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2), 16));
                }
            }

        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        String expectedDigest = "01";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigest);
    }
    public String convertASCIIStringToHexString(String asciiStr) {
        char[] ch = asciiStr.toCharArray();

        StringBuilder builder = new StringBuilder();
        for (char c : ch) {
            int i = (int) c;
            builder.append(Integer.toHexString(i));
            if (builder.length() % 2 != 0) {
                builder.insert(builder.length()-1, '0');
            }
        }
        return  builder.toString();
    }
}
