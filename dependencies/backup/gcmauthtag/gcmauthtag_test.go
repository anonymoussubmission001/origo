package gcmauthtag_test

import (
	f "gcmauthtag"
	"testing"
)

func TestAuthGCM(t *testing.T) {

	// AES GCM parameters used to generate input ciphers:
	// key: "7fddb57453c241d03efbed3ac44e371c"
	// none: "ee283a3fc75575e33efd4887"
	// additional data: ""
	// plaintext: "d5de42b461646c255c87bd2962d3b9a2"

	// expected result: cipherPlaintext||tag: "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3"

	tagMaskCipher := "598d3ea40503b2563c8843964ff8125b"   // tagMask E(nonce||ctr=1)
	plaintextCipher := "2ccda4a5415cb91e135c2a0f78c9b2fd" // ciphertext chunks E(nonce||ctr=2...)
	galoisKexCipher := "122204f9d2a456649d2bb1f744c939d9" // H  E(16bytes zeros)
	lengthPlaintext := 16
	lengthAdditionalData := 0

	expectedResult := "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3"

	tag := f.AuthGCM(tagMaskCipher, plaintextCipher, galoisKexCipher, lengthPlaintext, lengthAdditionalData)

	// fmt.Println("final tag:", tag)

	if tag != expectedResult {
		t.Fatal("Tag calculation failed.")
	}
}

func TestDynAuthGCM(t *testing.T) {

	// AES GCM parameters used to generate input ciphers:
	// key: "fe47fcce5fc32665d2ae399e4eec72ba"
	// none: "5adb9609dbaeb58cbd6e7275"
	// additional data: "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a"
	// plaintext: "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429"

	// expected result: cipherPlaintext||tag ->
	// -> "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269a05f29e57a8288ea330a0a43b6089d55"

	tagMaskCipher := "0ecdbfd066ef0d37dede986f3996f21f" // tagMask E(nonce||ctr=1)
	// plaintextCipher is response ciphertext without last 16bytes
	plaintextCipher := "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269" // ciphertext chunks E(nonce||ctr=2...)
	galoisKexCipher := "63abbe3f64001ff58abafbcac4957bde"                                                                 // H  E(16bytes zeros)
	additional := "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a"
	expectedResult := "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269a05f29e57a8288ea330a0a43b6089d55"

	tag := f.DynAuthGCM(tagMaskCipher, plaintextCipher, galoisKexCipher, additional)

	if tag != expectedResult {
		t.Fatal("Tag calculation failed.")
	}
}

// todo: add chunks of ciphertext
// todo: add handling of additional data

// proxy/verifier

// 1. verify tag
// - get tagMaskCipher
// - get galoiskey
// - compute tag and see if it matches
// - evaluate circuit for tagMaskCipher computation
// - evaluate circuit for galoiskey computation

// 2. verify starting position and locator circuit
// - prover call regex and determines block numbers
// - verify ciphertext chunks decrypt aes-gcm, block 5-6, block 5 (80-96), block 6 (96-112), block 7 (112-128)
// - verify locator circuit
// 	- index block 5 = byte block_index 80 (disclosed by prover, public)
// 	- policy starting_position index 92 (disclosed by prover, public), policy value length 10 bytes (92-102)
// - in circuit compute in plaintext array, array access: substring = plaintext_chunk5||plaintext_chunk6||plaintext_chunk7[starting_position-block_index : len(json_key)]
// - substring comparison: json_key (comes from policy) == substring

// middlecontent_regex "\":\ \"" -> provide that in policy
// provide in policy -> json_key
// provide in policy -> json_key.byteslength
// provide in policy -> float dot position or number digits of integer

// we use our own server to have deterministic content

// one value: substring = json_key||middlecontent_regex, e.g. "\"stock_value\":\ \""

// get value_string
// integer_str = plaintext_chunk5||plaintext_chunk6||plaintext_chunk7[starting_position-block_index+len(substring) : digits_integer]
// yinnan has the example of conversion: str to int
// integer_number = int(integer_str)
// policy_statement(integer_number) -> true or false

//////////////////////////////////////////////
// (
// - index_start_middlecontent = len(json_key) + 92 = 97
// middlecontent = plaintext_chunk5||plaintext_chunk6||plaintext_chunk7[starting_position-block_index+len(json_key) : len(middlecontent)]
// middlecontent == middlecontent_regex
// number_str = plaintext_chunk5||plaintext_chunk6||plaintext_chunk7[starting_position-block_index+len(json_key)+len(middlecontent) : len(bytes_value)]
// )

// conversion?
// number_str

//////////////////////////////////////////////

// 1. receive values: starting pos index
// 2. divide response data body by 16, then take chunk 5-7 check if decryption circuit fulfills that
// 3. take tagMaskCipher and galoisKey and cipherchunks (except last 16 bytes tag) ,
// 		then compute tag with AuthGCM and compare tag.
//
// expectedResult := "2ccda4a5415cb91e135c2a0f78c9b2fd 2ccda4a5415cb91e135c2a0f78c9b2f d2ccda4a5415cb91e135c2a0f78c9b2fd 2ccda4a5415cb91e135c2a0f78c9b2fd 2ccda4a5415cb91e135c2a0f78c9b2fd 2ccda4a5415cb91e135c2a0f78c9b2fd 2ccda4a5415cb91e135c2a0f78c9b2fd b36d1df9b9d5e596f83e8b7f52971cb3"
