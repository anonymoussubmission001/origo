package examples.gadgets.kdc;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.aes_gcm.DynamicAESGCMGadget;

import java.util.Arrays;


public class KDCOPTGadget extends Gadget {

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

    private int blockNr;
    private int startBlockIdx;


//    public KDCOPTGadget (Wire[] HS, Wire[] SHTSInnerHashOutput, Wire[] kfsInnerHashOutput, Wire[] sfInnerHashOutput,
//                         Wire[] dHSInnerHashOutput, Wire[] MSInnerHashOutput, Wire[] SATSInnerHashOutput,
//                         Wire[] CATSInnerHashOutput, Wire[] kSAPPKeyInnerHashOutput, Wire[] kSAPPIVInnerHashOutput,
//                         Wire[] kCAPPKeyInnerHashOutput, Wire[] kCAPPIVInnerHashOutput, Wire[] plaintextChunks,
//                        Wire[] ciphertextChunks, Wire[] circuitInputSF,int blockNr,
//                         int startBlockIdx, int keyValuePairLen, int offsetKeyValuePair, int offsetValue,
//                        int floatStringLen, int dotIdx, String... desc) {
public KDCOPTGadget (Wire[] HS, Wire[] SHTSInnerHashOutput, Wire[] kfsInnerHashOutput, Wire[] sfInnerHashOutput,
                     Wire[] dHSInnerHashOutput, Wire[] MSInnerHashOutput, Wire[] SATSInnerHashOutput,
                     Wire[] CATSInnerHashOutput, Wire[] kSAPPKeyInnerHashOutput, Wire[] kSAPPIVInnerHashOutput,
                     Wire[] kCAPPKeyInnerHashOutput, Wire[] kCAPPIVInnerHashOutput, Wire[] plaintextChunks,
                     Wire[] ciphertextChunks, Wire[] circuitInputSF, Wire[] seqCounter, int startBlockIdx, String... desc) {
        super(desc);

        this.HS = HS;
        this.SHTSInnerHashOutput = SHTSInnerHashOutput;
        this.kfsInnerHashOutput = kfsInnerHashOutput;
        this.sfInnerHashOutput = sfInnerHashOutput;
        this.dHSInnerHashOutput = dHSInnerHashOutput;
        this.MSInnerHashOutput = MSInnerHashOutput;
        this.SATSInnerHashOutput = SATSInnerHashOutput;
        this.CATSInnerHashOutput = CATSInnerHashOutput;
        this.kSAPPKeyInnerHashOutput = kSAPPKeyInnerHashOutput;
        this.kSAPPIVInnerHashOutput = kSAPPIVInnerHashOutput;
        this.kCAPPKeyInnerHashOutput = kCAPPKeyInnerHashOutput;
        this.kCAPPIVInnerHashOutput = kCAPPIVInnerHashOutput;
        this.plaintextChunks = plaintextChunks;
        this.startBlockIdx = startBlockIdx;
        this.ciphertextChunks = ciphertextChunks;
        this.circuitInputSF = circuitInputSF;
        this.seqCounter = seqCounter;
        this.output = new Wire[1];
        buildCircuit();
    }

    protected void buildCircuit() {

        Wire[] SHTS = new KDCOPTOuterHMACGadget(HS,SHTSInnerHashOutput).getOutputWires();
        Wire[] SHTSByteFormat = formatOutput(SHTS);
        Wire[] kfs = new KDCOPTOuterHMACGadget(SHTSByteFormat,kfsInnerHashOutput).getOutputWires();
        Wire[] kfsByteFormat = formatOutput(kfs);
        Wire[] SF = new KDCOPTOuterHMACGadget(kfsByteFormat, sfInnerHashOutput).getOutputWires();
        Wire[] SFByteFormat = formatOutput(SF);
        Wire tmp = SFByteFormat[0].isEqualTo(circuitInputSF[0]);
        for (int i = 1; i < SFByteFormat.length; i++) {
            tmp = SFByteFormat[i].isEqualTo(circuitInputSF[i]).and(tmp);
        }

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
//        proof of the query is not considered
//        Wire[] kCAPPKeyByteFormat = formatOutput(kCAPPKey);
//        kCAPPKeyByteFormat = truncate(kCAPPKeyByteFormat, 16);
//        Wire[] kCAPPIVByteFormat = formatOutput(kCAPPIV);
//        kCAPPIVByteFormat = truncate(kCAPPIVByteFormat, 12);
        for (int i = 0; i < 8; i++) {
            kSAPPIVByteFormat[4 + i] = kSAPPIVByteFormat[4 + i].getBitWires(8).
                    xorWireArray(seqCounter[i].getBitWires(8)).packAsBits();
        }
        Wire[] CT = new DynamicAESGCMGadget(kSAPPKeyByteFormat,kSAPPIVByteFormat, plaintextChunks, startBlockIdx).getOutputWires();
        for (int i = 0; i < CT.length; i++) {
            tmp = CT[i].isEqualTo(ciphertextChunks[i]).and(tmp);
        }
        output[0] = tmp;


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

    @Override
    public Wire[] getOutputWires() {
        return output;
    }
}