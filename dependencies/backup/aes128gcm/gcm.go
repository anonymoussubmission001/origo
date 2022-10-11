// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes128gcm

import (
	// subtleoverlap "crypto/internal/subtle"

	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// AEAD is a cipher mode providing authenticated encryption with associated
// data. For a description of the methodology, see
//	https://en.wikipedia.org/wiki/Authenticated_encryption
type AEAD interface {
	// NonceSize returns the size of the nonce that must be passed to Seal
	// and Open.
	NonceSize() int

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//
	// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the
	// additional data and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the additional data must match the
	// value passed to Seal.
	//
	// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// gcmAble is an interface implemented by ciphers that have a specific optimized
// implementation of GCM, like crypto/aes. NewGCM will check for this interface
// and return the specific AEAD if found.
type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (AEAD, error)
}

// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//   the coefficient of x⁰ can be obtained by v.low >> 63.
//   the coefficient of x⁶³ can be obtained by v.low & 1.
//   the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//   the coefficient of x¹²⁷ can be obtained by v.high & 1.
type gcmFieldElement struct {
	low, high uint64
}

// gcm represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	cipher    Block
	nonceSize int
	tagSize   int
	// productTable contains the first sixteen powers of the key, H.
	// However, they are in bit reversed order. See NewGCMWithNonceSize.
	productTable [16]gcmFieldElement
}

// NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode
// with the standard nonce length.
//
// In general, the GHASH operation performed by this implementation of GCM is not constant-time.
// An exception is when the underlying Block was created by aes.NewCipher
// on systems with hardware support for AES. See the crypto/aes package documentation for details.
func NewGCM(cipher Block) (AEAD, error) {
	fmt.Println("calling NewGCM")
	// log.Println("calling NewGCM")
	return newGCMWithNonceAndTagSize(cipher, gcmStandardNonceSize, gcmTagSize)
}

// NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which accepts nonces of the given length. The length must not
// be zero.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard nonce lengths. All other users should use
// NewGCM, which is faster and more resistant to misuse.
func NewGCMWithNonceSize(cipher Block, size int) (AEAD, error) {
	return newGCMWithNonceAndTagSize(cipher, size, gcmTagSize)
}

// NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which generates tags with the given length.
//
// Tag sizes between 12 and 16 bytes are allowed.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard tag lengths. All other users should use
// NewGCM, which is more resistant to misuse.
func NewGCMWithTagSize(cipher Block, tagSize int) (AEAD, error) {
	return newGCMWithNonceAndTagSize(cipher, gcmStandardNonceSize, tagSize)
}

func newGCMWithNonceAndTagSize(cipher Block, nonceSize, tagSize int) (AEAD, error) {
	if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
		return nil, errors.New("cipher: incorrect tag size given to GCM")
	}

	if nonceSize <= 0 {
		return nil, errors.New("cipher: the nonce can't have zero length, or the security of the key will be immediately compromised")
	}

	if cipher, ok := cipher.(gcmAble); ok {
		return cipher.NewGCM(nonceSize, tagSize)
	}

	if cipher.BlockSize() != gcmBlockSize {
		return nil, errors.New("cipher: NewGCM requires 128-bit block cipher")
	}

	var key [gcmBlockSize]byte
	fmt.Println("KEY newGCM:", key)
	fmt.Println("KEY (HEX) in newGCM:", hex.EncodeToString(key[:]))
	cipher.Encrypt(key[:], key[:])
	// I think thats the key H used for the authentication...
	// multiplication key of GMAC, makes sense, its the encryption of 128/16bytes zeros under regular key.
	// TODO verify that!!

	fmt.Println("ENC KEY newGCM:", key)
	fmt.Println("ENC KEY (HEX) in newGCM:", hex.EncodeToString(key[:]))
	fmt.Printf("ENC KEY (bit): %b", key)

	g := &gcm{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize}

	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := gcmFieldElement{
		binary.BigEndian.Uint64(key[:8]),
		binary.BigEndian.Uint64(key[8:]),
	}
	fmt.Println("key[:8]", key[:8])
	fmt.Println("key[8:]", key[8:])
	fmt.Println("HEX key[:8]", hex.EncodeToString(key[:8]))
	fmt.Println("HEX key[8:]", hex.EncodeToString(key[8:]))
	// type gcmFieldElement struct {
	// 	low, high uint64
	// }

	fmt.Println("first gcmFieldElement x:", x)
	fmt.Println("result of reverseBits(1)=", reverseBits(1))
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		fmt.Println("reverseBits(i)=", reverseBits(i))
		fmt.Println("reverseBits(i+1)=", reverseBits(i+1))

		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}
	fmt.Println("productTable:", g.productTable)

	return g, nil
}

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	gcmStandardNonceSize = 12
)

func (g *gcm) NonceSize() int {
	return g.nonceSize
}

func (g *gcm) Overhead() int {
	return g.tagSize
}

func (g *gcm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(g.cipher.BlockSize()) {
		panic("crypto/cipher: message too large for GCM")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+g.tagSize)
	// if subtleoverlap.InexactOverlap(out, plaintext) {
	// 	panic("crypto/cipher: invalid buffer overlap")
	// }

	fmt.Println("len(plaintext)+g.tagSize:", len(plaintext)+g.tagSize)
	fmt.Println("sliceForAppend ret:", ret)
	fmt.Println("sliceForAppend out:", out)

	var counter, tagMask [gcmBlockSize]byte
	fmt.Println("first counter:", counter)
	fmt.Println("first counter as hex:", hex.EncodeToString(counter[:]))
	fmt.Println("first tagMask:", tagMask)
	fmt.Println("first tagMask as hex:", hex.EncodeToString(tagMask[:]))

	g.deriveCounter(&counter, nonce)
	fmt.Println("after deriving counter, counter=", counter)
	fmt.Println("counter as hex:", hex.EncodeToString(counter[:]))

	g.cipher.Encrypt(tagMask[:], counter[:])
	fmt.Println("-- after encrypting tagMask with counter --")
	fmt.Println("-- after encrypt counter:", counter)
	fmt.Println("-- after encrypt counter as hex:", hex.EncodeToString(counter[:]))
	fmt.Println("-- after encrypt tagMask:", tagMask)
	fmt.Println("-- after encrypt tagMask as hex:", hex.EncodeToString(tagMask[:]))

	gcmInc32(&counter)

	fmt.Println("1. gcm incrementing counter:", counter)

	fmt.Println("--- NOW running counterCrypt --- ")
	// out keeps track of latest encryptions, with double of 16 byte size to store authentication tag in the end.
	g.counterCrypt(out, plaintext, &counter)

	fmt.Println("--- after counterCrypt --- ")
	fmt.Println("out:", out)
	fmt.Println("hex out:", hex.EncodeToString(out))
	fmt.Println("plaintext:", plaintext)
	fmt.Println("hex plaintext:", hex.EncodeToString(plaintext))
	fmt.Println("counter:", counter)
	fmt.Println("hex counter:", hex.EncodeToString(counter[:]))

	var tag [gcmTagSize]byte
	fmt.Println("tag: ", tag, "with size:", len(tag))

	fmt.Println("::: NOW NOW NOW GCM AUTH ::: ")
	// auth calculates authentication tag and stores it in tag block array
	fmt.Println("--- tag empty until here ")
	fmt.Println("-- out contains encrypted mask with counter xor plaintext")
	fmt.Println("-- data is emtpy in all our test cases")
	fmt.Println("-- tagMask is encrytion of initial 1 counter||nonce")
	g.auth(tag[:], out[:len(plaintext)], data, &tagMask)

	fmt.Println("TAG RESULT:", tag)
	fmt.Println("HEX TAG RESULT:", hex.EncodeToString(tag[:]))

	fmt.Println("out before tag copy:", out)
	fmt.Println("len(plaintext):", len(plaintext), "len(tag):", len(tag))
	fmt.Println("copying into out[from plain length: end], from the whole tag array")
	// auth tag is put to the end of the out array
	// out is the data that keeps track of encrypted plaintexts..
	copy(out[len(plaintext):], tag[:])

	fmt.Println("final out:", out)
	fmt.Println("final HEX out:", hex.EncodeToString(out))
	fmt.Println("final ret:", ret)

	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *gcm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if g.tagSize < gcmMinimumTagSize {
		panic("crypto/cipher: incorrect GCM tag size")
	}

	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(g.cipher.BlockSize())+uint64(g.tagSize) {
		return nil, errOpen
	}

	// tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	var counter, tagMask [gcmBlockSize]byte
	g.deriveCounter(&counter, nonce)

	g.cipher.Encrypt(tagMask[:], counter[:])
	gcmInc32(&counter)

	var expectedTag [gcmTagSize]byte
	g.auth(expectedTag[:], ciphertext, data, &tagMask)

	ret, out := sliceForAppend(dst, len(ciphertext))
	// if subtleoverlap.InexactOverlap(out, ciphertext) {
	// 	panic("crypto/cipher: invalid buffer overlap")
	// }

	// if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
	// 	// The AESNI code decrypts and authenticates concurrently, and
	// 	// so overwrites dst in the event of a tag mismatch. That
	// 	// behavior is mimicked here in order to be consistent across
	// 	// platforms.
	// 	for i := range out {
	// 		out[i] = 0
	// 	}
	// 	return nil, errOpen
	// }

	g.counterCrypt(out, ciphertext, &counter)

	return ret, nil
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
func gcmAdd(x, y *gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
func gcmDouble(x *gcmFieldElement) (double gcmFieldElement) {

	fmt.Println("")
	fmt.Println(":::::::::::::GCM DOUBLE FUNCTION:::::::::::")
	fmt.Println("x.high:", x.high)
	fmt.Println("x.high&1:", x.high&1)
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	fmt.Println("x.high >> 1:", x.high>>1)
	fmt.Println("x.low << 63:", x.low<<63)
	fmt.Println("double.high |= x.low << 63:", x.high>>1|x.low<<63)
	fmt.Println("x.low >> 1:", x.low>>1)
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
		fmt.Println("double.low = double.low XOR 0xe100000000000000:", double.low)
	}

	fmt.Println("")
	fmt.Println("")
	return
}

var gcmReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// mul sets y to y*H, where H is the GCM key, fixed during NewGCMWithNonceSize.
func (g *gcm) mul(y *gcmFieldElement) {
	var z gcmFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(gcmReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions. See the comment
			// in NewGCMWithNonceSize.
			t := &g.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func (g *gcm) updateBlocks(y *gcmFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= binary.BigEndian.Uint64(blocks)
		y.high ^= binary.BigEndian.Uint64(blocks[8:])
		g.mul(y)
		blocks = blocks[gcmBlockSize:]
	}
}

// update extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
func (g *gcm) update(y *gcmFieldElement, data []byte) {
	fullBlocks := (len(data) >> 4) << 4
	g.updateBlocks(y, data[:fullBlocks])

	if len(data) != fullBlocks {
		var partialBlock [gcmBlockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		g.updateBlocks(y, partialBlock[:])
	}
}

// gcmInc32 treats the final four bytes of counterBlock as a big-endian value
// and increments it.
func gcmInc32(counterBlock *[16]byte) {
	ctr := counterBlock[len(counterBlock)-4:]
	fmt.Println("gcm Increment, ctr and size", ctr, len(ctr))
	fmt.Println("binary.BigEndian.Uint32=", binary.BigEndian.Uint32(ctr))
	binary.BigEndian.PutUint32(ctr, binary.BigEndian.Uint32(ctr)+1)
	fmt.Println("counter update, ctr and size:", ctr, len(ctr))
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// counterCrypt crypts in to out using g.cipher in counter mode.
func (g *gcm) counterCrypt(out, in []byte, counter *[gcmBlockSize]byte) {
	// input: out=out, in=plaintext,*counter= &counter

	var mask [gcmBlockSize]byte

	fmt.Println("mask", mask, ", with size:", len(mask))
	// in = plaintext
	fmt.Println("size in/plaintext:", len(in))

	i := 0
	for len(in) >= gcmBlockSize {
		fmt.Println("inside counterCrypt, len(in/plaintext) >= gcmBlockSize")

		fmt.Println("encrypt hex counter", hex.EncodeToString(counter[:]))
		g.cipher.Encrypt(mask[:], counter[:])
		fmt.Println("counter:", counter)
		fmt.Println("hex counter:", hex.EncodeToString(counter[:]))
		fmt.Println("mask:", mask)
		fmt.Println("hex mask:", hex.EncodeToString(mask[:]))

		fmt.Println("increment counter")
		gcmInc32(counter)
		fmt.Println("counter after increment:", counter)

		fmt.Println("calling xorWords in counterCrypt")
		fmt.Println("input out:", out)
		fmt.Println("input in/plaintext:", in, hex.EncodeToString(in))
		fmt.Println("input mask:", mask, hex.EncodeToString(mask[:]))

		// xor words assumes 16 bytes plaintext that will be masked?
		xorWords(out, in, mask[:])
		fmt.Println("output out :", i, out, hex.EncodeToString(out[:16]))
		fmt.Println("output in/plaintext:", in)
		fmt.Println("output mask:", mask)

		out = out[gcmBlockSize:]
		fmt.Println("out = out[16:end]", out)
		in = in[gcmBlockSize:]
		fmt.Println("in/plaintext=in[16:end]")
		i = i + 1
	}

	if len(in) > 0 {
		fmt.Println("inside counterCrypt, len(in/plaintext) > 0")

		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		xorBytes(out, in, mask[:])
	}
}

// deriveCounter computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
func (g *gcm) deriveCounter(counter *[gcmBlockSize]byte, nonce []byte) {
	// GCM has two modes of operation with respect to the initial counter
	// state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
	// for nonces of other lengths. For a 96-bit nonce, the nonce, along
	// with a four-byte big-endian counter starting at one, is used
	// directly as the starting counter. For other nonce sizes, the counter
	// is computed by passing it through the GHASH function.
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		var y gcmFieldElement
		g.update(&y, nonce)
		y.high ^= uint64(len(nonce)) * 8
		g.mul(&y)
		binary.BigEndian.PutUint64(counter[:8], y.low)
		binary.BigEndian.PutUint64(counter[8:], y.high)
	}
}

// auth calculates GHASH(ciphertext, additionalData), masks the result with
// tagMask and writes the result to out.
func (g *gcm) auth(out, ciphertext, additionalData []byte, tagMask *[gcmTagSize]byte) {
	// input: tag[:], out[:len(plaintext)], data, &tagMask
	fmt.Println("-- inside auth --")
	fmt.Println("out=tag[:]:", out)
	fmt.Println("hex out:", hex.EncodeToString(out))
	fmt.Println("ciphertext=out[:len(plaintext)]:", ciphertext)
	fmt.Println("hex ciphertext:", hex.EncodeToString(ciphertext))
	fmt.Println("additionalData=data:", additionalData)
	fmt.Println("hex additionalData:", hex.EncodeToString(additionalData))
	fmt.Println("*tagMask=&tagMask:", tagMask)
	fmt.Println("hex tagMask:", hex.EncodeToString(tagMask[:]))

	var y gcmFieldElement
	g.update(&y, additionalData)
	g.update(&y, ciphertext)

	y.low ^= uint64(len(additionalData)) * 8
	y.high ^= uint64(len(ciphertext)) * 8

	g.mul(&y)

	binary.BigEndian.PutUint64(out, y.low)
	binary.BigEndian.PutUint64(out[8:], y.high)

	xorWords(out, out, tagMask[:])
}
