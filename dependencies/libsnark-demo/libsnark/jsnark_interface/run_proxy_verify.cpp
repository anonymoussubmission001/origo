#include <string>
#include <iostream>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include "CircuitReader.hpp"
#include "libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"


int main(int argc, char* argv[]) {
    cout << "proxy: verify..." <<endl;
    libff::start_profiling();
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    if (argc != 16) {
        cout << "invalid number of args" <<endl;
        throw std::invalid_argument("The number of args should be 7");
    }


    string SHTSInnerHashOutput = argv[1];
    string kfsInnerHashOutput = argv[2];
    string sfInnerHashOutput = argv[3];
    string dHSInnerHashOutput = argv[4];
    string MSInnerHashOutput = argv[5];
    string SATSInnerHashOutput = argv[6];
    string CATSInnerHashOutput = argv[7];
    string kSAPPKeyInnerHashOutput = argv[8];
    string kSAPPIVInnerHashOutput = argv[9];
    string kCAPPKeyInnerHashOutput = argv[10];
    string kCAPPIVInnerHashOutput = argv[11];
    string circuitInputSF = argv[12];
    string ciphertextChunks = argv[13];
    string seqCounter = argv[14];
    string thresholdValue = argv[15];

    string statement_in_8bits = SHTSInnerHashOutput + kfsInnerHashOutput + sfInnerHashOutput + dHSInnerHashOutput + MSInnerHashOutput + SATSInnerHashOutput + CATSInnerHashOutput
            + kSAPPKeyInnerHashOutput + kSAPPIVInnerHashOutput + kCAPPKeyInnerHashOutput + kCAPPIVInnerHashOutput + circuitInputSF + ciphertextChunks +
            seqCounter;
    string statement_in_non_8bits = thresholdValue;
//    1 : "threshold" + 1: "input one " 1 : "output one"
    const int num_inputs = statement_in_8bits.length()/2 + 1 + 1 + 1;

    VariableArray input(num_inputs, "input");

    // "1" for const one-input
    pb->val(input[0]) = readFieldElementFromHex("1");

    int input_idx = 1;
    for (int i = 0; i < statement_in_8bits.length(); i += 2)
    {
        char tmp[2];
        string str = statement_in_8bits.substr(i, i+2);
        tmp[0] = str[0];
        tmp[1] = str[1];
        pb->val(input[input_idx]) = readFieldElementFromHex(tmp);
//        cout << "input[" << input_idx << "]="  << tmp << endl;
        input_idx++;
    }

    istringstream is(statement_in_non_8bits);
    long long i;
    is >> i;
    std::ostringstream ss;
    ss << std::setfill('0') << std::setw(16) << std::hex << i;
    std::string threshold_hex_str = ss.str();
    char threshold_hex_char[threshold_hex_str.length() + 1];
    strcpy(threshold_hex_char, threshold_hex_str.c_str());
    pb->val(input[input_idx++]) = readFieldElementFromHex(threshold_hex_char);

    // "1" for correct output
    pb->val(input[input_idx]) = readFieldElementFromHex("1");

    std::fstream pr("proof.raw", std::ios_base::in);
    r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof;
    pr >> proof;
    pr.close();

    std::fstream vkf("vk.raw", std::ios_base::in);
    r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> vk;
    vkf >> vk;
    vkf.close();

    const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),full_assignment.begin() + num_inputs);

    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_gg_ppzksnark_pp>(vk, primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

}