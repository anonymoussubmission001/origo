package examples.generators.proxy;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.comparator.GTFloatThresholdComparatorGadget;
import examples.gadgets.comparator.LTFloatThresholdComparatorGadget;
import examples.gadgets.comparator.EQFloatComparatorGadget;
import examples.gadgets.comparator.JSONKeyValuePairComparatorGadget;
import examples.gadgets.kdc.KDCOPTGadget;

import java.math.BigInteger;

public class ProxyAppGenerator2 extends CircuitGenerator {
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

    private Wire[] plaintextChunks;
    private Wire[] ciphertextChunks;

    private Wire[] circuitInputSF;
    private Wire[] seqCounter;

    private Wire[] thresholdValue;


    private int blockNr;
    private int startBlockIdx;
    private int keyValuePairLen;
    private int offsetKeyValuePair;
    private int offsetValue;
    private int floatStringLen;
    private int dotIdx;
    private String keyValueStartPattern;


    private String HSStr;
    private String SHTSInnerHashStr;
    private String kfsInnerHashStr;
    private String sfInnerHashStr;
    private String dHSInnerHashStr;
    private String MSHSInnerHashStr;
    private String SATSInnerHashStr;
    private String CATSInnerHashStr;
    private String kSAPPKeyInnerHashStr;
    private String kSAPPIVInnerHashStr;
    private String kCAPPKeyInnerHashStr;
    private String kCAPPIVInnerHashStr;
    private String plaintextStr;
    private String SFStr;
    private String SeqCounterStr;
    private String ciphertextStr;

    // needs to be changed to String instead of BigInteger
    private String threshold;
    // private BigInteger threshold;

    private int compareMaxBitLength;

    public ProxyAppGenerator2(String circuitName) {
        super(circuitName);
    }

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
        plaintextChunks = createProverWitnessWireArray(16*blockNr);

        circuitInputSF = createInputWireArray(32);
        ciphertextChunks = createInputWireArray(16*blockNr);
        seqCounter = createInputWireArray(8);

	// for equality check, change createInputWireArray to floatStringLen instead of 1
        thresholdValue = createInputWireArray(floatStringLen);
        Wire tmp;

	// key derivation circuit
        tmp = new KDCOPTGadget(HS, SHTSInnerHashOutput,  kfsInnerHashOutput, sfInnerHashOutput,
                dHSInnerHashOutput, MSInnerHashOutput, SATSInnerHashOutput,
                CATSInnerHashOutput, kSAPPKeyInnerHashOutput, kSAPPIVInnerHashOutput,
                kCAPPKeyInnerHashOutput, kCAPPIVInnerHashOutput, plaintextChunks,
                ciphertextChunks, circuitInputSF, seqCounter, startBlockIdx).getOutputWires()[0];

	// substring locator in plaintextChunks
        Wire[] keyValuePair = new Wire[keyValuePairLen];
        System.arraycopy(plaintextChunks, offsetKeyValuePair, keyValuePair,0,keyValuePair.length);
        String jsonKeyStr = convertASCIIStringToHexString(keyValueStartPattern);
        output = new JSONKeyValuePairComparatorGadget(plaintextChunks, plaintextChunks.length, keyValuePair, offsetKeyValuePair,
                keyValuePairLen, jsonKeyStr).getOutputWires();
	// verifies substring inclusing
        tmp = tmp.and(output[0]);

	// copy plaintextChunks into floatString for float comparison
        Wire[] floatString = new Wire[floatStringLen];
        System.arraycopy(plaintextChunks, offsetValue, floatString , 0, floatStringLen);

	// float comparator statement
        Wire compResult = new EQFloatComparatorGadget(floatString, floatStringLen, dotIdx,
                thresholdValue, compareMaxBitLength).getOutputWires()[0];

	// verify float comparator
        output[0] = tmp.and(compResult);

        makeOutputArray(output, "digest");
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
//        // IBM example
//        blockNr = 3;
//        startBlockIdx = 47;
//        String HSStr = "8cb3ba573ece6265ad79a8ccb3d18ad092972fe14ebec9cc5324c27e74445b45";
//        String SHTSInnerHashStr = "159c99e7aeea2e869e82ffb3bb39734e3338a293e4b2705c46d2bac98c725246";
//        String kfsInnerHashStr = "46205f67e2e6a844bb065140ebe8b10f3d574e9dbfd68065a9f55451d34f8d11";
//        String sfInnerHashStr = "e9760e0041c1c7d8f15faa8431c2b8a53646a1fa934b8b0b7ceab13538f0da4f";
//        String dHSInnerHashStr = "1a4b1284f65b13c1867ae82d6395cc0ca0ba32d0da269f3dc26fbf5a47685b6e";
//        String MSHSInnerHashStr = "cafa45b3b34e6c8866eae9ee30b6403157d2cb7dad76ec83b280e8066deb027d";
//        String SATSInnerHashStr = "fcbb9c7471a8e02dd9b164666505140cf4e04f20bcd22b36d0567d2d4f3fdf90";
//        String CATSInnerHashStr = "86d094eaedd720a5ed5804803fdd3dab00619aaf17eabedc0c68ee2c61b98990";
//        String kSAPPKeyInnerHashStr = "3aa4b0e3c2e37f684195689aeaa0185ffe61ac453427170733d12b2004ef369c";
//        String kSAPPIVInnerHashStr = "da329bf1c8b0a78191784d64662b8912571d03e6bb90bf409f7ef38297953a60";
//        String kCAPPKeyInnerHashStr = "0fab063e8bb1922d742363902ccf63cd01b56c67392fcf8241cc7f2b1694b54a";
//        String kCAPPIVInnerHashStr = "131a88a05608fa49a2e524afba3efa62fe806c2fa7bc4b24f7865661f9774e14";
//        String plaintextStr = "43222c0a202020202020202022382e20426964205072696365223a202232313735392e3939303030303030222c0a2020";
//        String SFStr = "18f590c85facbda0da9969d6ccfe34276bc53ffcb2a492f1d845cdf415b7d794";
//        String SeqCounterStr = "0000000000000000";
//        String ciphertextStr = "22b0c07892c89150cc2eb317bbf3a742c2abbc901fbcea091bd65de776bd0f297ffb9f94971f1ccc6807a7299def0936";

//       // IBM example
//       // blockNr = 4;
//       //startBlockIdx = 55;
//        String HSStr = "017105fd3cc9982dead79d55872b2dc5d1f5d31eacf05176bb88760822830c8a";
//        String SHTSInnerHashStr = "d06aca76d932a7416307406ba9d6e7f0a81a1746e0534ecf47c0630de05a4190";
//        String kfsInnerHashStr = "f785392853bc7185b32237e27234dfb6972b7ed6d9a59039b5e7908dd7108721";
//        String sfInnerHashStr = "62a0c26cef161696de86adec73af5927b63ebe0b63fe518b810d0d5afb1fb394";
//        String dHSInnerHashStr = "3b9ea0606266fce6590d933f66aed1ef308efa5c442cef41adac4cb91102b5c9";
//        String MSHSInnerHashStr = "08b66f20f3fc94ed6071a04b2b970bb736be8183e68f30660c6be25253d6abaf";
//        String SATSInnerHashStr = "8b6ccf99db95f7907c89aa7fe2d8d29256c1248e5a96621ec661c2e895f95eb3";
//        String CATSInnerHashStr = "0d91a522ca40e282c0428cfcddecfb1cff1f88105b608eaf05c0328e016efa8e";
//        String kSAPPKeyInnerHashStr = "7c4bdea459a2b630e87795821a55c3d21b7a913c3e9855409c2fa2158e6ddbe6";
//        String kSAPPIVInnerHashStr = "280f94a36bde4aaa89dfec7b0977c436b7569abe39b963555d3681850dbb651d";
//        String kCAPPKeyInnerHashStr = "f7a79059c7292ae61721b6f923c2a140bf79938034604e3b6d8f7b419ba00967";
//        String kCAPPIVInnerHashStr = "1cb91a1b7ed085abb6ad11342068b15daab9c5ccc7a3ace3874aae7c3a8abbf2";
//        String plaintextStr = "20202022323032322d30372d30372031353a31383a3030223a207b0a20202020202020202020202022312e206f70656e223a20223134312e31383030222c0a20";
//        String SFStr = "2447bcc716852c4fea100fe20c0b9d88ac3e13351371cdebafd0db80cb2b611e";
//        String SeqCounterStr = "0000000000000009";
//        String ciphertextStr = "e299486297f0c3a99796fbae87eb1cda0d867b9ed7eff0505fb2cb9dd915954f1a0a325a6b334aa9b44c05e430bb51e0470a8a0e9370e7d81319ee488f6b8108";

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
	// change threshold to setWires as well in case of EQ
        setWires2(thresholdValue, threshold, circuitEvaluator);
        // circuitEvaluator.setWireValue(thresholdValue[0], threshold);
    }

    private void setWires2(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
        for (int i = 0; i < inputStr.length(); i++) {
            circuitEvaluator.setWireValue(wires[i], BigInteger.valueOf(inputStr.charAt(i)));
        }
    }

    private void setWires(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
        for (int i = 0; i < inputStr.length()/2; i++) {
            circuitEvaluator.setWireValue(wires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2), 16));
        }
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

    public static void main(String[] args) throws Exception {
        Config.hexOutputEnabled = true;
        ProxyAppGenerator2 generator = new ProxyAppGenerator2("ProxyApp2_Circuit");
        if (args.length == 0) {
//            // BTC example
//            generator.blockNr = 3;
//            generator.startBlockIdx = 47;
//            generator.keyValuePairLen = 33;
//            generator.offsetKeyValuePair = 12;
//            generator.offsetValue = 29;
//            generator.floatStringLen = 14;
//            generator.dotIdx = 5;
//            generator.keyValueStartPattern = "\"8. Bid Price\": ";
//
//            generator.HSStr = "f096223e8d5dba834ec9a14a9463b9cc34da5577492912199f8ad445770a0b8f";
//            generator.SHTSInnerHashStr = "ec8911766316093debb3e20e4f8ad528c3c18e3acc75d321e84a283bde1c6af2";
//            generator.kfsInnerHashStr = "02c5de05c782c0b37eb8a9de0b292c6ffb8071454bccedf534eff57f1d481ac6";
//            generator.sfInnerHashStr = "5cb7ab42f60427029f9a4da369d3345e35b97cbef33d9a1813d1b8f5de44b53a";
//            generator.dHSInnerHashStr = "bc17bbd6bb92830b83ca6a418df7daeb326a2ee829517bfe537e2d772a5d4275";
//            generator.MSHSInnerHashStr = "134a2f2200b22b009697119b55a7b8480e6290e3409e0baa0fb3106eb1ff979d";
//            generator.SATSInnerHashStr = "56939cc4f653850678db0309bea540b9e453271b48ac0a35b87b7ad9dd620367";
//            generator.CATSInnerHashStr = "51017742494c230f195803173488966d0cd4d096dbbfd5ebefa1437bb3c69183";
//            generator.kSAPPKeyInnerHashStr = "f139b0b77e79f8a64e21d5b2b30a4ac457eb70e66122b24462751d15713fa04d";
//            generator.kSAPPIVInnerHashStr = "7cdeb6a3daaf2f788a521db7509d9b8d52bb4d7975af2b7a3aed9aba23262d73";
//            generator.kCAPPKeyInnerHashStr = "41b2ad7b8f2887b321b786d4e35c7cc36c4239a9244101e391c02f8bb586e108";
//            generator.kCAPPIVInnerHashStr = "6401c020d27797c2269cc8d5b04815ad9d1e04963049731e06719180cb2a7252";
//            generator.plaintextStr = "43222c0a202020202020202022382e20426964205072696365223a202232303437302e3737303030303030222c0a2020";
//            generator.SFStr = "34b30b56a9de5852b04b0a479c419d50aee1ed7fdc65d7f134e07ff8ce133b71";
//            generator.SeqCounterStr = "0000000000000000";
//            generator.ciphertextStr = "72f5e31158097c4f7bdf1a23b8ce55224f51622423d339b4d49d571e861a8f722d030ee2996145c1f3815b1cde633182";
//            generator.threshold = new BigInteger("2047067000000"); // scaled 10x
//            generator.compareMaxBitLength = 40;

//            // IBM example
            generator.blockNr = 4;
            generator.startBlockIdx = 4;
            generator.keyValuePairLen = 59;
            generator.offsetKeyValuePair = 0;
            generator.offsetValue = 49;
            generator.floatStringLen = 8;
            generator.dotIdx = 3;
            generator.keyValueStartPattern = "\"2022-07-08 14:55:00\": {\n            \"1. open\": \"";

            generator.HSStr = "e9b1d92d1935f26a40d452ab0fd604881641ee97e142a82c5a434af04fb78c44";
            generator.SHTSInnerHashStr = "499979f088b74f1055eed455f1d764590f0815ba2dc2b4fe009198223c012873";
            generator.kfsInnerHashStr = "75295d4574e3c6b25766c693aa05b19c1ff5146d39e4abca35b77937f50b6e2f";
            generator.sfInnerHashStr = "fc890bba1c455bbcab4e120b10cce69858e70565f7a3ae8c0553de9fd8c1187d";
            generator.dHSInnerHashStr = "6d7d503805f5e0d9076cf4ecd57f00833da01b11d5798aaea131886fb2ed5fef";
            generator.MSHSInnerHashStr = "4beff4e1f5b32c576642950a4426c84e31a7e76b442efd34839f1f6ecccaf05a";
            generator.SATSInnerHashStr = "d14d6dd0c0a774ba5b807f8fccab48f076708e8c59abfaf76cc5215fb18a5863";
            generator.CATSInnerHashStr = "9497b322fc7b44cf428b5aa230a5441dc7b0ff1dfa234b728f7a686b3777c5c7";
            generator.kSAPPKeyInnerHashStr = "63c0311991de9a6e1c4a07aeb4cc3bbe4f3ea950eb19904f947e58c9457710f4";
            generator.kSAPPIVInnerHashStr = "96045f763d4bb52e0a7fb070f0e5490ecf61cff25283b6594b24c875ab951100";
            generator.kCAPPKeyInnerHashStr = "b39afe3258e35f68bbf1de379b78db390d5f761fae3030f92457515c5edbfe14";
            generator.kCAPPIVInnerHashStr = "a75fcb710c29ee7c8bef8e538838b7327423f6d839778a748b4f8c710a020a47";
            generator.plaintextStr = "22323032322d30372d30382031343a35353a3030223a207b0a20202020202020202020202022312e206f70656e223a20223134302e37393030222c0a20202020";
            generator.SFStr = "f7deb8fb4674964bc55e769de43b2d53bf1c8a27274445c241d017752f80cada";
            generator.SeqCounterStr = "000000000000000e";
            generator.ciphertextStr = "604ee028a674c4f56b1b53f1849b91f32209075617af63ac849d5cbd167564ddfdcb0272c68b19e7f48a0bce6a3da430384f3f7812646678e0996c600738bb90";
            // generator.threshold = new BigInteger("1406000"); // scaled 10x
            generator.threshold = "140.6000"; // scaled 10x
            generator.compareMaxBitLength = 24;

//        // BTC localhost example
//            generator.blockNr = 2;
//            generator.startBlockIdx = 30;
//            generator.keyValuePairLen = 18;
//            generator.offsetKeyValuePair = 13;
//            generator.offsetValue = 22;
//            generator.floatStringLen = 7;
//            generator.dotIdx = 5;
//            generator.keyValueStartPattern = "\"price\":\"";
//
//            generator.HSStr = "04a58170602e72a980824fdc60865faf325e1a894b9c723cc5a423752996e0f6";
//            generator.SHTSInnerHashStr = "112b5850acb7fd75fe8f4092c356b569b8f02907eaebee4c0b0dc03886ac92f0";
//            generator.kfsInnerHashStr = "6383680126cb49d4ca6c8d92ec7aac8730c40435a44b324a3a7e2674ee76a61d";
//            generator.sfInnerHashStr = "4c077f3f34e1d3fb5238fb0e198f52b228f941be1efdbe787cdf665799dee674";
//            generator.dHSInnerHashStr = "48911e8a5b54e0185de7f933f8ee185632cde9fd88531183ec380cb43b7c1198";
//            generator.MSHSInnerHashStr = "76c9bf8620d4e3faa1ace4bda0a233f0e4c993c1fd8c474e3c987976ef35eb46";
//            generator.SATSInnerHashStr = "164c587e1fab57439a068e264ad2c80577ba34a611801991b72b3cd589ca3e0e";
//            generator.CATSInnerHashStr = "a17cb4914037982799c110e2617dd9a7f0687ee094efb9be7da668c021a1f1f2";
//            generator.kSAPPKeyInnerHashStr = "26f26a24462563ab93d62f4ffbf23789dc1f3412633b8bbf8c1509c04b162358";
//            generator.kSAPPIVInnerHashStr = "aef0e12dd3579fa59c82ba2921723281e13a0343a55886dd141193183b1491d4";
//            generator.kCAPPKeyInnerHashStr = "2e651e2f16feadf0b5e55345a652353420cec11b87052bd9d81542a905fa5135";
//            generator.kCAPPIVInnerHashStr = "acc8cfdf651b58d2b97f738e284f0369ebb13ddbe4531783dda170abf07d62ca";
//            generator.plaintextStr = "302c353631204575726f227d2c227072696365223a2233383030322e32222c22";
//            generator.SFStr = "4294b43a9f2579c43b951a65ae57431804be96c9c71613ea5eeebfc83a91fbf5";
//            generator.SeqCounterStr = "0000000000000000";
//            generator.ciphertextStr = "74ddda545b8233a6f41fb7fc70669c30249282ca8271a47e7f57c860943caac9";
//            generator.threshold = new BigInteger("380021"); // scaled 10x
//            generator.compareMaxBitLength = 20;
        } else {
            generator.blockNr = Integer.parseInt(args[0]);
            generator.startBlockIdx = Integer.parseInt(args[1]);
            generator.keyValuePairLen = Integer.parseInt(args[2]);
            generator.offsetKeyValuePair = Integer.parseInt(args[3]);
            generator.offsetValue = Integer.parseInt(args[4]);
            generator.floatStringLen = Integer.parseInt(args[5]);
            generator.dotIdx = Integer.parseInt(args[6]);
            generator.keyValueStartPattern = args[7];
            generator.HSStr = args[8];
            generator.SHTSInnerHashStr = args[9];
            generator.kfsInnerHashStr = args[10];
            generator.sfInnerHashStr = args[11];
            generator.dHSInnerHashStr = args[12];
            generator.MSHSInnerHashStr = args[13];
            generator.SATSInnerHashStr = args[14];
            generator.CATSInnerHashStr = args[15];
            generator.kSAPPKeyInnerHashStr = args[16];
            generator.kSAPPIVInnerHashStr = args[17];
            generator.kCAPPKeyInnerHashStr = args[18];
            generator.kCAPPIVInnerHashStr = args[19];
            generator.plaintextStr = args[20];
            generator.SFStr = args[21];
            generator.SeqCounterStr = args[22];
            generator.ciphertextStr = args[23];
	    // change threshold in EQ case to just args[24]
            generator.threshold = args[24]; // scaled 10x
            // generator.threshold = new BigInteger(args[24]); // scaled 10x
            generator.compareMaxBitLength = Integer.parseInt(args[25]);
        }
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }
}



