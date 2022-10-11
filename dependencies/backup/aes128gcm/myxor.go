package aes128gcm

func MyXor(inp1, inp2 []byte) (xor []byte) {

	xor = make([]byte, len(inp1))
	for i := range inp1 {
		xor[i] = inp1[i] ^ inp2[i]
	}

	return
}
