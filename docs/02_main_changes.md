# What's the difference

## Modified TLS vs Original TLS
_ORIGO_ uses the adapted go 1.19.1 TLS 1.3 functionality. The [oohttp](https://github.com/ooni/oohttp) library is used to support the underlying modified _ORIGO_ TLS.
We list the main changes to the original TLS library:
- support passing policy through the `NextProtos` field of TLS `Config` with the keyword "pol:". The same method with the keyword "loc" is applied to the location that specifies the extracted information from the policy.
- extend the TLS Config structure internally for internal configuration and storage of the related data for further usage during the following TLS session.
- a collection of crypto primitive functions in `crypto_util.go` are available for block-wise constructing the desired circuits.
- provide KDC-opt related functions are available in `hmac_md_helper.go` and `key_derivation_circuit.go`. The Merkle-Darmgard constructed optimization happens in the handshake during the TLS session and post-process steps after the response. Please see the file `handshake_client_tls13.go`.
- provide policy-related functions, e.g., creating policy according to the policy configuration, locating the position of contained key-value pair etc.
- support TLS records parser. The proxy can parse the saved records and authenticate the data. see `tls_parser_record.go`.

## Modified Jsnark vs Original Jsnark
The extended jsnark clone supports more gadgets, generators, and tests, which can be found in jsnark's `dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples`.
We list some notes about main changes below:

Gadgets:
- __DynamicAESGCMGadget__: This AES-GCM gadget supports dynamic length. It includes the __AES128WrapperGadget__ for only arbitrary length of AES encryption and the Xor16Gadget.
- __KDCOPTOuterHMACGadget__: This includes a SHA256 circuit to achieve the outer hash function of the HMAC. It is used as a sub-gadgets of the KDCOPTGadget.
- __KDCOPTGadget__: This is an optimized key derivation circuit with layered-hash-proofs optimization. It involves __DynamicAESGCMGadget__ and __KDCOPTOuterHMACGadget__ to prove the inputs which generate the ciphertext.
- __SHA256DECOGadget__: This is an enhanced SHA256 circuit for providing flexible IV as inputs and can be used in block-wise optimization of chained mode.
- __FloatThresholdComparatorGadget__: This is a gadget for proving the floating-point value is above a given threshold.
- __JSONKeyValuePairComparatorGadget__: This is a gadget for proving the key-value pair of JSON files fulfilled the key-value pattern, i.e., the pair begin with a double quote ("), followed by a key, a semicolon and a double quote (") again, in the meanwhile, the pair ends with a double quote and comma.

Different corresponding examples and tests are provided in the generators and tests sub-folders, respectively. An example of a complete _ORIGO_ proof is the __ProxyAppGenerator__ in `ProxyAppGenerator.java`. It includes a __KDCOPTGadget__, a __JSONKeyValuePairComparatorGadget__, and a XXFloatThresholdComparatorGadget, which corresponds to the three stages to achieve the functionality of _ORIGO_. In the first stage, it checks whether the circuit can obtain the corresponding ciphertext from the given inputs. Afterward, it compares content with the key-value pattern. In the final stage, it checks if the floating-point number of the JSON file is over the predetermined threshold. Only all the checks are passed, then it can return 1.

The connection between jsnark and libsnary is based on the giving jsnark produced `.in` and `.arith` files. Therefore, the underlying submodule libsnark is enhanced to support the extended jsnark. Based on the original `libsnark/jsnark_interface/run_ppzksnark.cpp`, we separate the process into two files:
- `run_generate_prove`: generating the proving key, verifying key, and proof.
- `run_proxy_verify`: verifying the proof.

