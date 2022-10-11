package tls

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"reflect"
)

func SHA256Gadget(message []byte, iv []byte, padding bool, previousLen int) ([]byte, error) {
	if message == nil || iv == nil {
		return nil, errors.New("SHA256 compression: This version does not support nil input")
	}
	if len(message)%64 != 0 && !padding {
		return nil, errors.New("SHA256 compression: wrong message length")
	}
	h0 := uint32(iv[0])<<24 + uint32(iv[1])<<16 + uint32(iv[2])<<8 + uint32(iv[3])
	h1 := uint32(iv[4])<<24 + uint32(iv[5])<<16 + uint32(iv[6])<<8 + uint32(iv[7])
	h2 := uint32(iv[8])<<24 + uint32(iv[9])<<16 + uint32(iv[10])<<8 + uint32(iv[11])
	h3 := uint32(iv[12])<<24 + uint32(iv[13])<<16 + uint32(iv[14])<<8 + uint32(iv[15])
	h4 := uint32(iv[16])<<24 + uint32(iv[17])<<16 + uint32(iv[18])<<8 + uint32(iv[19])
	h5 := uint32(iv[20])<<24 + uint32(iv[21])<<16 + uint32(iv[22])<<8 + uint32(iv[23])
	h6 := uint32(iv[24])<<24 + uint32(iv[25])<<16 + uint32(iv[26])<<8 + uint32(iv[27])
	h7 := uint32(iv[28])<<24 + uint32(iv[29])<<16 + uint32(iv[30])<<8 + uint32(iv[31])

	k := [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}
	var padded []byte
	if padding {
		if previousLen%64 != 0 {
			return nil, errors.New("SHA256 compression: wrong message length")
		}
		padded = append(message, 0x80)
		if len(padded)%64 <= 56 {
			suffix := make([]byte, 56-(len(padded)%64))
			padded = append(padded, suffix...)
		} else {
			suffix := make([]byte, 64+56-(len(padded)%64))
			padded = append(padded, suffix...)
		}
		msgLen := len(message)*8 + previousLen*8
		bs := make([]byte, 8)
		binary.BigEndian.PutUint64(bs, uint64(msgLen))
		padded = append(padded, bs...)
	} else {
		padded = message
	}

	broken := [][]byte{}
	for i := 0; i < len(padded)/64; i++ {
		broken = append(broken, padded[i*64:i*64+63])
	}
	for _, chunk := range broken {
		w := []uint32{}
		for i := 0; i < 16; i++ {
			w = append(w, binary.BigEndian.Uint32(chunk[i*4:i*4+4]))
		}
		w = append(w, make([]uint32, 48)...)

		for i := 16; i < 64; i++ {
			s0 := rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
			s1 := rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		for i := 0; i < 64; i++ {
			S1 := rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
			ch := (e & f) ^ ((^e) & g)
			temp1 := h + S1 + ch + k[i] + w[i]
			S0 := rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}
		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
		h5 = h5 + f
		h6 = h6 + g
		h7 = h7 + h
	}
	hashBytes := [][]byte{iToB(h0), iToB(h1), iToB(h2), iToB(h3), iToB(h4), iToB(h5), iToB(h6), iToB(h7)}
	hash := []byte{}
	for i := 0; i < 8; i++ {
		hash = append(hash, hashBytes[i]...)
	}

	return hash, nil
}

func iToB(i uint32) []byte {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, i)
	return bs
}

func rightRotate(n uint32, d uint) uint32 {
	return (n >> d) | (n << (32 - d))
}

var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var inv_sbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

var rcon = [10]uint32{
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
	0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
}

type AES struct {
	nr        int      // number of rounds
	nk        int      // number of words in the key
	nb        int      // number of words in a block
	len       int      // length(byte) of block
	key       []byte   // key
	roundKeys []uint32 // round keys generated from key.
}

// NewAES returns a pointer of type AES and an error.
//
// key: The following algorithms will be used based on the size of the key:
//
// 16 bytes = AES-128
//
// 24 bytes = AES-192
//
// 32 bytes = AES-256
func NewAES(key []byte) (*AES, error) {
	var nk, nr int
	switch len(key) {
	case 16:
		nk = 4
		nr = 10
	case 24:
		nk = 6
		nr = 12
	case 32:
		nk = 8
		nr = 14
	default:
		return nil, errors.New("invalid key length")
	}
	aes := AES{
		nr:  nr,
		nk:  nk,
		nb:  4,
		len: 16,
		key: key,
	}
	aes.roundKeys = aes.keyExpansion()
	return &aes, nil
}

// keyExpansion returns an uint32 slice presenting round keys
// (4 uint32 for a key) in encryption. The number of round keys
// is determined by the type of encryption. For example, 11 round
// keys in AES-128.
func (a *AES) keyExpansion() []uint32 {
	var w []uint32
	for i := 0; i < a.nk; i++ { // little-endian or big-endian matters.
		w = append(w, binary.BigEndian.Uint32(a.key[4*i:4*i+4]))
	}
	for i := a.nk; i < a.nb*(a.nr+1); i++ {
		tempW := make([]byte, 4)
		binary.BigEndian.PutUint32(tempW, w[i-1])
		if i%a.nk == 0 {
			rotWord(tempW)
			a.subBytes(tempW)
			tempRcon := make([]byte, 4)
			binary.BigEndian.PutUint32(tempRcon, rcon[i/a.nk-1])
			Xor(tempW, tempRcon)
		} else if a.nk > 6 && i%a.nk == 4 {
			a.subBytes(tempW)
		}
		w = append(w, w[i-a.nk]^binary.BigEndian.Uint32(tempW))
	}
	// mute debugging
	//utils.DumpWords("keyExpansion:", w)
	return w
}

// EncryptCTR returns the ciphertext of CTR-mode encryption.
// The iv must be 128bit.
func (a *AES) EncryptCTR(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	plainTmp := make([]byte, len(in))
	copy(plainTmp, in)
	ivNumber := big.NewInt(0).SetBytes(iv)
	one := big.NewInt(1)

	i := 0
	for ; i < len(plainTmp)-a.len; i += a.len {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(plainTmp[i:i+a.len], ivTmp)
		ivNumber.Add(ivNumber, one).FillBytes(ivTmp)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(plainTmp[i:], ivTmp)

	//fmt.Printf("aes_impl-%d CTR encrypted ciphertext:", a.nk*32)
	//utils.DumpBytes("", plainTmp)
	return plainTmp
}

// DecryptCTR returns the plaintext of CTR-mode decryption.
// The iv must be 128bit.
// It is exactly the same with EncryptCTR.
func (a *AES) DecryptCTR(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	cipherTmp := make([]byte, len(in))
	copy(cipherTmp, in)
	ivNumber := big.NewInt(0).SetBytes(iv)
	one := big.NewInt(1)

	i := 0
	for ; i < len(cipherTmp)-a.len; i += a.len {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(cipherTmp[i:i+a.len], ivTmp)
		ivNumber.Add(ivNumber, one).FillBytes(ivTmp)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(cipherTmp[i:], ivTmp)

	//fmt.Printf("aes_impl-%d CTR decrypted ciphertext:", a.nk*32)
	//utils.DumpBytes("", cipherTmp)
	return cipherTmp
}

// EncryptGCM returns the ciphertext of GCM-mode encryption and the tag.
func (a *AES) EncryptGCM(in []byte, iv []byte, auth []byte, tagLen int) ([]byte, []byte) {
	H := make([]byte, 16)
	a.encryptBlock(H, a.roundKeys)
	var J0 []byte

	if len(iv) == 12 {
		J0 = append(iv, []byte{0x00, 0x00, 0x00, 0x01}...)
	} else {
		sPlus64Zeros := make([]byte, 16*int(math.Ceil(float64(8*len(iv))/128.0))-len(iv)+8)
		lenIV := make([]byte, 8)
		big.NewInt(int64(8 * len(iv))).FillBytes(lenIV)
		J0 = gHash(append(append(iv, sPlus64Zeros...), lenIV...), H)
	}
	J0Tmp := make([]byte, len(J0))
	copy(J0Tmp, J0)

	cipher := a.EncryptGCTR(in, inc32(J0))
	vZeros := make([]byte, 16*int(math.Ceil(float64(8*len(auth))/128.0))-len(auth))
	uZeros := make([]byte, 16*int(math.Ceil(float64(8*len(cipher))/128.0))-len(cipher))
	lenA := make([]byte, 8)
	lenC := make([]byte, 8)
	big.NewInt(int64(8 * len(auth))).FillBytes(lenA)
	big.NewInt(int64(8 * len(cipher))).FillBytes(lenC)
	S := gHash(append(append(append(append(append(auth, vZeros...), cipher...), uZeros...), lenA...), lenC...), H)
	T := a.EncryptGCTR(S, J0Tmp)
	//fmt.Printf("aes_impl-%d GCM encrypted ciphertext:", a.nk*32)
	//utils.DumpBytes("", cipher)
	//utils.DumpBytes("tag:", T[:tagLen])
	return cipher, T[:tagLen]
}

// DecryptGCM returns the plaintext of GCM-mode decryption or
// a nil if authentication failed.
func (a *AES) DecryptGCM(in []byte, iv []byte, auth []byte, tag []byte) []byte {
	H := make([]byte, 16)
	a.encryptBlock(H, a.roundKeys)
	var J0 []byte

	if len(iv) == 12 {
		J0 = append(iv, []byte{0x00, 0x00, 0x00, 0x01}...)
	} else {
		sPlus64Zeros := make([]byte, 16*int(math.Ceil(float64(8*len(iv))/128.0))-len(iv)+8)
		lenIV := make([]byte, 8)
		big.NewInt(int64(8 * len(iv))).FillBytes(lenIV)
		J0 = gHash(append(append(iv, sPlus64Zeros...), lenIV...), H)
	}
	J0Tmp := make([]byte, len(J0))
	copy(J0Tmp, J0)

	ciphertext := make([]byte, len(in))
	copy(ciphertext, in)
	plaintext := a.EncryptGCTR(in, inc32(J0))
	vZeros := make([]byte, 16*int(math.Ceil(float64(8*len(auth))/128.0))-len(auth))
	uZeros := make([]byte, 16*int(math.Ceil(float64(8*len(plaintext))/128.0))-len(plaintext))
	lenA := make([]byte, 8)
	lenC := make([]byte, 8)
	big.NewInt(int64(8 * len(auth))).FillBytes(lenA)
	big.NewInt(int64(8 * len(plaintext))).FillBytes(lenC)
	S := gHash(append(append(append(append(append(auth, vZeros...), ciphertext...), uZeros...), lenA...), lenC...), H)
	T := a.EncryptGCTR(S, J0Tmp)
	//fmt.Printf("aes_impl-%d GCM decrypted plaintext:", a.nk*32)
	if reflect.DeepEqual(T[:len(tag)], tag) {
		//utils.DumpBytes("", plaintext)
		return plaintext
	}
	//utils.DumpBytes("\nFailed", nil)
	return nil
}

// gHash hashes X with the sub key H, and it returns a new slice.
func gHash(X []byte, H []byte) []byte {
	y := make([]byte, 16)

	for i := 0; i < len(X); i += 16 {
		Xor(y, X[i:i+16])
		mulBlock(y, H)
	}
	return y
}

// EncryptGCTR encrypts plaintext in with initial counter block ICB.
func (a *AES) EncryptGCTR(in []byte, ICB []byte) []byte {
	if in == nil {
		return in
	}

	plainTmp := make([]byte, len(in))
	copy(plainTmp, in)
	xorBlock := make([]byte, 16*int(math.Ceil(float64(len(plainTmp))/16.0)))
	// The variable cbi(i 'th counter block) is used to preserve the state.
	cbi := make([]byte, 16)
	cbi1 := make([]byte, 16)
	copy(cbi, ICB)
	copy(cbi1, ICB)
	for i := 0; i < len(plainTmp); i += a.len {
		a.encryptBlock(cbi1, a.roundKeys)
		copy(xorBlock[i:i+a.len], cbi1)
		cbi = inc32(cbi)
		copy(cbi1, cbi)
	}

	Xor(plainTmp, xorBlock)
	return plainTmp
}

// subBytes operation in AES encryption.
func (a *AES) subBytes(state []byte) {
	for i, v := range state {
		state[i] = sbox[v]
	}
}

// invSubBytes operation in AES decryption.
func (a *AES) invSubBytes(state []byte) {
	for i, v := range state {
		state[i] = inv_sbox[v]
	}
}

func (a *AES) shiftRow(in []byte, i int, n int) {
	in[i], in[i+4*1], in[i+4*2], in[i+4*3] = in[i+4*(n%4)], in[i+4*((n+1)%4)], in[i+4*((n+2)%4)], in[i+4*((n+3)%4)]
}

// rotWord rotates a 4-byte slice leftward. That is in << 8.
func rotWord(in []byte) {
	in[0], in[1], in[2], in[3] = in[1], in[2], in[3], in[0]
}

// shiftRows operation in AES encryption.
func (a *AES) shiftRows(state []byte) {
	a.shiftRow(state, 1, 1)
	a.shiftRow(state, 2, 2)
	a.shiftRow(state, 3, 3)
}

// invShiftRows operation in AES decryption.
func (a *AES) invShiftRows(state []byte) {
	a.shiftRow(state, 1, 3)
	a.shiftRow(state, 2, 2)
	a.shiftRow(state, 3, 1)
}

// xtime returns the result of multiplication by x in GF(2^8).
func xtime(in byte) byte {
	return (in << 1) ^ (((in >> 7) & 1) * 0x1b)
}

// xtimes returns the result of multiplication by x^ts in GF(2^8).
func xtimes(in byte, ts int) byte {
	for ts > 0 {
		in = xtime(in)
		ts--
	}
	return in
}

// mulByte returns byte x multiplied by byte y in GF(2^8).
func mulByte(x byte, y byte) byte {
	return (((y >> 0) & 0x01) * xtimes(x, 0)) ^
		(((y >> 1) & 0x01) * xtimes(x, 1)) ^
		(((y >> 2) & 0x01) * xtimes(x, 2)) ^
		(((y >> 3) & 0x01) * xtimes(x, 3)) ^
		(((y >> 4) & 0x01) * xtimes(x, 4)) ^
		(((y >> 5) & 0x01) * xtimes(x, 5)) ^
		(((y >> 6) & 0x01) * xtimes(x, 6)) ^
		(((y >> 7) & 0x01) * xtimes(x, 7))
}

// mulWord provides the one-column mix for the function
// mixColumns and invMixColumns. In fact, it's a matrix
// multiplication.
func mulWord(x []byte, y []byte) {
	tmp := make([]byte, 4)
	copy(tmp, x)

	x[0] = mulByte(tmp[0], y[3]) ^ mulByte(tmp[1], y[0]) ^ mulByte(tmp[2], y[1]) ^ mulByte(tmp[3], y[2])
	x[1] = mulByte(tmp[0], y[2]) ^ mulByte(tmp[1], y[3]) ^ mulByte(tmp[2], y[0]) ^ mulByte(tmp[3], y[1])
	x[2] = mulByte(tmp[0], y[1]) ^ mulByte(tmp[1], y[2]) ^ mulByte(tmp[2], y[3]) ^ mulByte(tmp[3], y[0])
	x[3] = mulByte(tmp[0], y[0]) ^ mulByte(tmp[1], y[1]) ^ mulByte(tmp[2], y[2]) ^ mulByte(tmp[3], y[3])
}

// mixColumns operation in AES encryption.
func (a *AES) mixColumns(state []byte) {
	s := []byte{0x03, 0x01, 0x01, 0x02}
	for i := 0; i < len(state); i += 4 {
		mulWord(state[i:i+4], s)
	}
}

// invMixColumns operation in AES decryption.
func (a *AES) invMixColumns(state []byte) {
	s := []byte{0x0b, 0x0d, 0x09, 0x0e}
	for i := 0; i < len(state); i += 4 {
		mulWord(state[i:i+4], s)
	}
}

// Xor applies y xor to x. Please make sure that len(y) >= len(x).
func Xor(x []byte, y []byte) {
	if len(x) <= len(y) {
		for i := 0; i < len(x); i++ {
			x[i] = x[i] ^ y[i]
		}
	}
}

// addRoundKey operation in AES.
func (a *AES) addRoundKey(state []byte, w []uint32) {
	tmp := make([]byte, a.len)
	for i := 0; i < len(w); i += 1 {
		binary.BigEndian.PutUint32(tmp[4*i:4*i+4], w[i])
	}
	Xor(state, tmp)
}

// encryptBlock encrypts one block in the plaintext.
func (a *AES) encryptBlock(state []byte, roundKeys []uint32) {
	a.addRoundKey(state, roundKeys[0:4])
	for round := 1; round < a.nr; round++ {
		a.subBytes(state)
		a.shiftRows(state)
		a.mixColumns(state)
		a.addRoundKey(state, roundKeys[4*round:4*round+4])
	}
	a.subBytes(state)
	a.shiftRows(state)
	a.addRoundKey(state, roundKeys[a.nr*4:a.nr*4+4])
}

// decryptBlock decrypts one block in the ciphertext.
func (a *AES) decryptBlock(state []byte, roundKeys []uint32) {
	a.addRoundKey(state, roundKeys[a.nr*4:a.nr*4+4])
	for round := a.nr - 1; round > 0; round-- {
		a.invShiftRows(state)
		a.invSubBytes(state)
		a.addRoundKey(state, roundKeys[4*round:4*round+4])
		a.invMixColumns(state)
	}
	a.invShiftRows(state)
	a.invSubBytes(state)
	a.addRoundKey(state, roundKeys[0:4])
}

// inc increments the right-most 32 bits of the bit string X,
// and it returns X.
func inc32(X []byte) []byte {
	lsb32 := binary.BigEndian.Uint32(X[len(X)-4:]) + 1
	binary.BigEndian.PutUint32(X[len(X)-4:], lsb32)
	return X
}

// mulBlock impose a multiplication operation to x in GCM mode.
func mulBlock(x []byte, y []byte) {
	tmp := big.NewInt(0).SetBytes([]byte{0xe1})

	R := tmp.Lsh(tmp, 120)
	X := big.NewInt(0).SetBytes(x)
	Z := big.NewInt(0)
	V := big.NewInt(0).SetBytes(y)
	for i := 0; i < 128; i++ {
		if X.Bit(127-i) == 1 {
			Z.Xor(Z, V)
		}
		if V.Bit(0) == 0 {
			V.Rsh(V, 1)
		} else {
			V.Xor(V.Rsh(V, 1), R)
		}
	}
	Z.FillBytes(x)
}
