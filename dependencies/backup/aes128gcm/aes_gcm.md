
aes gcm algorithm
1. newCipher 
	-> the first block is a 16 bytes key
2. newGCM
	-> it initializes the gcm struct and with nonce 12 bytes and tagsize 16 bytes
	-> it also pre-fills the productTable
3. Seal
	-> counter is array of 16 bytes
	-> tagMask is array of 16 bytes
	-> derive counter from nonce
		-> we consider the fast path for 12 byte (96-bit) nonce
		-> counter will be the nonce and a 4 byte big endian counter starting at 1
	-> encrypt the tagMask array as destination with the counter array as source
	-> gcmInc32 function call on counter reference
		-> increment uint32 with putUint into reference address
	-> counterCrypt(out, plaintext, counter_reference)
	-> tag byte array
	-> gcm auth(tag byte array, output, extend_data, tagMask_array)


4. Open
	-> 

