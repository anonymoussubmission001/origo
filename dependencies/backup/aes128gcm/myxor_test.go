package aes128gcm_test

import (
	myxor "aes128gcm"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMyXor(t *testing.T) {
	fmt.Println("")
	fmt.Println("")
	fmt.Println("----------------")
	fmt.Println("test from myxor")
	fmt.Println("----------------")
	fmt.Println("")
	fmt.Println("")

	// 16 bytes plaintext
	inp1String := "d5de42b461646c255c87bd2962d3b9a2"
	inp1, _ := hex.DecodeString(inp1String)

	// input mask (encryption of zeros array with nonce||counter=3)
	inp2String := "f913e6112038d53b4fdb97261a1a0b5f"
	inp2, _ := hex.DecodeString(inp2String)

	fmt.Println("inp1:", inp1)
	fmt.Println("inp2:", inp2)

	xor := myxor.MyXor(inp1, inp2)

	fmt.Println("xor:", xor)

	fmt.Println("inp1:", inp1String)
	fmt.Println("inp2:", inp2String)
	fmt.Println("xor:", hex.EncodeToString(xor))

	// mynumb, _ := hex.DecodeString("d8")
	// fmt.Println("my calculation:", mynumb&1)

}
