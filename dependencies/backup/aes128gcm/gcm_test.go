// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes128gcm_test

import (
	"bytes"
	"crypto/aes"
	"fmt"

	// "crypto/cipher"
	cipher "aes128gcm"
	"encoding/hex"
	"testing"
)

var aesGCMTests = []struct {
	key, nonce, plaintext, ad, result string
}{
	// {
	// 	"11754cd72aec309bf52f7687212e8957",
	// 	"3c819d9a9bed087615030b65",
	// 	"",
	// 	"",
	// 	"250327c674aaf477aef2675748cf6971",
	// },
	// {
	// 	"ca47248ac0b6f8372a97ac43508308ed",
	// 	"ffd2b598feabc9019262d2be",
	// 	"",
	// 	"",
	// 	"60d20404af527d248d893ae495707d1a",
	// },
	// {
	// 	"fbe3467cc254f81be8e78d765a2e6333",
	// 	"c6697351ff4aec29cdbaabf2",
	// 	"",
	// 	"67",
	// 	"3659cdc25288bf499ac736c03bfc1159",
	// },
	// {
	// 	"8a7f9d80d08ad0bd5a20fb689c88f9fc",
	// 	"88b7b27d800937fda4f47301",
	// 	"",
	// 	"50edd0503e0d7b8c91608eb5a1",
	// 	"ed6f65322a4740011f91d2aae22dd44e",
	// },
	// {
	// 	"051758e95ed4abb2cdc69bb454110e82",
	// 	"c99a66320db73158a35a255d",
	// 	"",
	// 	"67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339f",
	// 	"6ce77f1a5616c505b6aec09420234036",
	// },
	// {
	// 	"77be63708971c4e240d1cb79e8d77feb",
	// 	"e0e00f19fed7ba0136a797f3",
	// 	"",
	// 	"7a43ec1d9c0a5a78a0b16533a6213cab",
	// 	"209fcc8d3675ed938e9c7166709dd946",
	// },
	// {
	// 	"7680c5d3ca6154758e510f4d25b98820",
	// 	"f8f105f9c3df4965780321f8",
	// 	"",
	// 	"c94c410194c765e3dcc7964379758ed3",
	// 	"94dca8edfcf90bb74b153c8d48a17930",
	// },
	// {
	// 	"7fddb57453c241d03efbed3ac44e371c",
	// 	"ee283a3fc75575e33efd4887",
	// 	"d5de42b461646c255c87bd2962d3b9a2",
	// 	"",
	// 	"2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3",
	// },
	// {
	// 	"ab72c77b97cb5fe9a382d9fe81ffdbed",
	// 	"54cc7dc2c37ec006bcc6d1da",
	// 	"007c5e5b3e59df24a7c355584fc1518d",
	// 	"",
	// 	"0e1bde206a07a9c2c1b65300f8c649972b4401346697138c7a4891ee59867d0c",
	// },
	{
		"fe47fcce5fc32665d2ae399e4eec72ba",
		"5adb9609dbaeb58cbd6e7275",
		"7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063",
		"88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
		"98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269e5db3e291ef1982e4defedaa2249f898556b47",
	},
	{
		"fe47fcce5fc32665d2ae399e4eec72ba",
		"5adb9609dbaeb58cbd6e7275",
		"7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429",
		"",
		"98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269f5f6e7d0b3d0418b82296ac7dd951d0e",
	},
	// {
	// 	"ec0c2ba17aa95cd6afffe949da9cc3a8",
	// 	"296bce5b50b7d66096d627ef",
	// 	"b85b3753535b825cbe5f632c0b843c741351f18aa484281aebec2f45bb9eea2d79d987b764b9611f6c0f8641843d5d58f3a242",
	// 	"f8d00f05d22bf68599bcdeb131292ad6e2df5d14",
	// 	"a7443d31c26bdf2a1c945e29ee4bd344a99cfaf3aa71f8b3f191f83c2adfc7a07162995506fde6309ffc19e716eddf1a828c5a890147971946b627c40016da1ecf3e77",
	// },
	// {
	// 	"2c1f21cf0f6fb3661943155c3e3d8492",
	// 	"23cb5ff362e22426984d1907",
	// 	"42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8",
	// 	"5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec",
	// 	"81824f0e0d523db30d3da369fdc0d60894c7a0a20646dd015073ad2732bd989b14a222b6ad57af43e1895df9dca2a5344a62cc57a3ee28136e94c74838997ae9823f3a",
	// },
	// {
	// 	"d9f7d2411091f947b4d6f1e2d1f0fb2e",
	// 	"e1934f5db57cc983e6b180e7",
	// 	"73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973aee6c312012f490c2c6f6166f4a59431e182663fcaea05a",
	// 	"0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a949822b639092d0e67015e86363583fcf0ca645af9f43375f05fdb4ce84f411dcbca73c2220dea03a20115d2e51398344b16bee1ed7c499b353d6c597af8",
	// 	"aaadbd5c92e9151ce3db7210b8714126b73e43436d242677afa50384f2149b831f1d573c7891c2a91fbc48db29967ec9542b2321b51ca862cb637cdd03b99a0f93b134",
	// },
	// {
	// 	"fe9bb47deb3a61e423c2231841cfd1fb",
	// 	"4d328eb776f500a2f7fb47aa",
	// 	"f1cc3818e421876bb6b8bbd6c9",
	// 	"",
	// 	"b88c5c1977b35b517b0aeae96743fd4727fe5cdb4b5b42818dea7ef8c9",
	// },
	// {
	// 	"6703df3701a7f54911ca72e24dca046a",
	// 	"12823ab601c350ea4bc2488c",
	// 	"793cd125b0b84a043e3ac67717",
	// 	"",
	// 	"b2051c80014f42f08735a7b0cd38e6bcd29962e5f2c13626b85a877101",
	// },
}

func TestAESGCM(t *testing.T) {
	for i, test := range aesGCMTests {

		fmt.Println("")
		fmt.Println("")
		fmt.Println("")
		fmt.Println("Test Case ", i)

		fmt.Println("")

		fmt.Println("key:", test.key)
		// fmt.Println("hex key:", hex.EncodeToString(test.key[:]))

		key, _ := hex.DecodeString(test.key)
		aes, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		nonce, _ := hex.DecodeString(test.nonce)
		plaintext, _ := hex.DecodeString(test.plaintext)
		ad, _ := hex.DecodeString(test.ad)
		tagSize := (len(test.result) - len(test.plaintext)) / 2

		fmt.Println("nonce:", nonce)
		fmt.Println("hex nonce:", test.nonce)
		fmt.Println("plaintext:", plaintext)
		fmt.Println("hex plaintext:", test.plaintext)
		fmt.Println("ad:", ad)
		fmt.Println("hex ad:", test.ad)
		fmt.Println("tagSize:", tagSize)
		fmt.Println("hex tagSize:", test.result)

		var aesgcm cipher.AEAD
		// switch {
		// // Handle non-standard tag sizes
		// case tagSize != 16:
		// 	aesgcm, err = cipher.NewGCMWithTagSize(aes, tagSize)
		// 	if err != nil {
		// 		t.Fatal(err)
		// 	}

		// // Handle 0 nonce size (expect error and continue)
		// case len(nonce) == 0:
		// 	aesgcm, err = cipher.NewGCMWithNonceSize(aes, 0)
		// 	if err == nil {
		// 		t.Fatal("expected error for zero nonce size")
		// 	}
		// 	continue

		// // Handle non-standard nonce sizes
		// case len(nonce) != 12:
		// 	aesgcm, err = cipher.NewGCMWithNonceSize(aes, len(nonce))
		// 	if err != nil {
		// 		t.Fatal(err)
		// 	}

		// default:
		aesgcm, err = cipher.NewGCM(aes)
		if err != nil {
			t.Fatal(err)
		}
		// }

		ct := aesgcm.Seal(nil, nonce, plaintext, ad)
		if ctHex := hex.EncodeToString(ct); ctHex != test.result {
			t.Errorf("#%d: got %s, want %s", i, ctHex, test.result)
			continue
		}

		fmt.Println("----------------------")
		fmt.Println("encryption done")
		fmt.Println("----------------------")

		plaintext2, err := aesgcm.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Errorf("#%d: Open failed", i)
			continue
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Errorf("#%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
			continue
		}

		// if len(ad) > 0 {
		// 	ad[0] ^= 0x80
		// 	if _, err := aesgcm.Open(nil, nonce, ct, ad); err == nil {
		// 		t.Errorf("#%d: Open was successful after altering additional data", i)
		// 	}
		// 	ad[0] ^= 0x80
		// }

		// nonce[0] ^= 0x80
		// if _, err := aesgcm.Open(nil, nonce, ct, ad); err == nil {
		// 	t.Errorf("#%d: Open was successful after altering nonce", i)
		// }
		// nonce[0] ^= 0x80

		// ct[0] ^= 0x80
		// if _, err := aesgcm.Open(nil, nonce, ct, ad); err == nil {
		// 	t.Errorf("#%d: Open was successful after altering ciphertext", i)
		// }
		// ct[0] ^= 0x80
	}
}

// func TestGCMInvalidTagSize(t *testing.T) {
// 	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")

// 	aes, _ := aes.NewCipher(key)

// 	for _, tagSize := range []int{0, 1, aes.BlockSize() + 1} {
// 		aesgcm, err := cipher.NewGCMWithTagSize(aes, tagSize)
// 		if aesgcm != nil || err == nil {
// 			t.Fatalf("NewGCMWithNonceAndTagSize was successful with an invalid %d-byte tag size", tagSize)
// 		}
// 	}
// }

// func TestTagFailureOverwrite(t *testing.T) {
// 	// The AESNI GCM code decrypts and authenticates concurrently and so
// 	// overwrites the output buffer before checking the authentication tag.
// 	// In order to be consistent across platforms, all implementations
// 	// should do this and this test checks that.

// 	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")
// 	nonce, _ := hex.DecodeString("54cc7dc2c37ec006bcc6d1db")
// 	ciphertext, _ := hex.DecodeString("0e1bde206a07a9c2c1b65300f8c649972b4401346697138c7a4891ee59867d0c")

// 	aes, _ := aes.NewCipher(key)
// 	aesgcm, _ := cipher.NewGCM(aes)

// 	dst := make([]byte, len(ciphertext)-16)
// 	for i := range dst {
// 		dst[i] = 42
// 	}

// 	result, err := aesgcm.Open(dst[:0], nonce, ciphertext, nil)
// 	if err == nil {
// 		t.Fatal("Bad Open still resulted in nil error.")
// 	}

// 	if result != nil {
// 		t.Fatal("Failed Open returned non-nil result.")
// 	}

// 	for i := range dst {
// 		if dst[i] != 0 {
// 			t.Fatal("Failed Open didn't zero dst buffer")
// 		}
// 	}
// }

// func TestGCMCounterWrap(t *testing.T) {
// 	// Test that the last 32-bits of the counter wrap correctly.
// 	tests := []struct {
// 		nonce, tag string
// 	}{
// 		{"0fa72e25", "37e1948cdfff09fbde0c40ad99fee4a7"},   // counter: 7eb59e4d961dad0dfdd75aaffffffff0
// 		{"afe05cc1", "438f3aa9fee5e54903b1927bca26bbdf"},   // counter: 75d492a7e6e6bfc979ad3a8ffffffff4
// 		{"9ffecbef", "7b88ca424df9703e9e8611071ec7e16e"},   // counter: c8bb108b0ecdc71747b9d57ffffffff5
// 		{"ffc3e5b3", "38d49c86e0abe853ac250e66da54c01a"},   // counter: 706414d2de9b36ab3b900a9ffffffff6
// 		{"cfdd729d", "e08402eaac36a1a402e09b1bd56500e8"},   // counter: cd0b96fe36b04e750584e56ffffffff7
// 		{"010ae3d486", "5405bb490b1f95d01e2ba735687154bc"}, // counter: e36c18e69406c49722808104fffffff8
// 		{"01b1107a9d", "939a585f342e01e17844627492d44dbf"}, // counter: e6d56eaf9127912b6d62c6dcffffffff
// 	}
// 	key, err := aes.NewCipher(make([]byte, 16))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	plaintext := make([]byte, 16*17+1)
// 	for i, test := range tests {
// 		nonce, _ := hex.DecodeString(test.nonce)
// 		want, _ := hex.DecodeString(test.tag)
// 		aead, err := cipher.NewGCMWithNonceSize(key, len(nonce))
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		got := aead.Seal(nil, nonce, plaintext, nil)
// 		if !bytes.Equal(got[len(plaintext):], want) {
// 			t.Errorf("test[%v]: got: %x, want: %x", i, got[len(plaintext):], want)
// 		}
// 		_, err = aead.Open(nil, nonce, got, nil)
// 		if err != nil {
// 			t.Errorf("test[%v]: authentication failed", i)
// 		}
// 	}
// }

// var _ cipher.Block = (*wrapper)(nil)

// type wrapper struct {
// 	block cipher.Block
// }

// func (w *wrapper) BlockSize() int          { return w.block.BlockSize() }
// func (w *wrapper) Encrypt(dst, src []byte) { w.block.Encrypt(dst, src) }
// func (w *wrapper) Decrypt(dst, src []byte) { w.block.Decrypt(dst, src) }

// // wrap wraps the Block interface so that it does not fulfill
// // any optimizing interfaces such as gcmAble.
// func wrap(b cipher.Block) cipher.Block {
// 	return &wrapper{b}
// }

// func TestGCMAsm(t *testing.T) {
// 	// Create a new pair of AEADs, one using the assembly implementation
// 	// and one using the generic Go implementation.
// 	newAESGCM := func(key []byte) (asm, generic cipher.AEAD, err error) {
// 		block, err := aes.NewCipher(key[:])
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		asm, err = cipher.NewGCM(block)
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		generic, err = cipher.NewGCM(wrap(block))
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		return asm, generic, nil
// 	}

// 	// check for assembly implementation
// 	var key [16]byte
// 	asm, generic, err := newAESGCM(key[:])
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if reflect.TypeOf(asm) == reflect.TypeOf(generic) {
// 		t.Skipf("no assembly implementation of GCM")
// 	}

// 	// generate permutations
// 	type pair struct{ align, length int }
// 	lengths := []int{0, 156, 8192, 8193, 8208}
// 	keySizes := []int{16, 24, 32}
// 	alignments := []int{0, 1, 2, 3}
// 	if testing.Short() {
// 		keySizes = []int{16}
// 		alignments = []int{1}
// 	}
// 	perms := make([]pair, 0)
// 	for _, l := range lengths {
// 		for _, a := range alignments {
// 			if a != 0 && l == 0 {
// 				continue
// 			}
// 			perms = append(perms, pair{align: a, length: l})
// 		}
// 	}

// 	// run test for all permutations
// 	test := func(ks int, pt, ad []byte) error {
// 		key := make([]byte, ks)
// 		if _, err := io.ReadFull(rand.Reader, key); err != nil {
// 			return err
// 		}
// 		asm, generic, err := newAESGCM(key)
// 		if err != nil {
// 			return err
// 		}
// 		if _, err := io.ReadFull(rand.Reader, pt); err != nil {
// 			return err
// 		}
// 		if _, err := io.ReadFull(rand.Reader, ad); err != nil {
// 			return err
// 		}
// 		nonce := make([]byte, 12)
// 		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 			return err
// 		}
// 		want := generic.Seal(nil, nonce, pt, ad)
// 		got := asm.Seal(nil, nonce, pt, ad)
// 		if !bytes.Equal(want, got) {
// 			return errors.New("incorrect Seal output")
// 		}
// 		got, err = asm.Open(nil, nonce, want, ad)
// 		if err != nil {
// 			return errors.New("authentication failed")
// 		}
// 		if !bytes.Equal(pt, got) {
// 			return errors.New("incorrect Open output")
// 		}
// 		return nil
// 	}
// 	for _, a := range perms {
// 		ad := make([]byte, a.align+a.length)
// 		ad = ad[a.align:]
// 		for _, p := range perms {
// 			pt := make([]byte, p.align+p.length)
// 			pt = pt[p.align:]
// 			for _, ks := range keySizes {
// 				if err := test(ks, pt, ad); err != nil {
// 					t.Error(err)
// 					t.Errorf("	key size: %v", ks)
// 					t.Errorf("	plaintext alignment: %v", p.align)
// 					t.Errorf("	plaintext length: %v", p.length)
// 					t.Errorf("	additionalData alignment: %v", a.align)
// 					t.Fatalf("	additionalData length: %v", a.length)
// 				}
// 			}
// 		}
// 	}
// }
