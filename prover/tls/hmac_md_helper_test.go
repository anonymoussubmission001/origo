package tls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

var hmacMDTestData = []struct {
	key, msg   string
	wantDigest string
}{
	{
		"6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19",
		"6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19",
		"6bca384dc990778d75620979886b904cda3a40a20c64b4c68777962781987fa9",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"1000000000000000000000000000000000",
		"9a95e6e39ca9b8d24c36f68bb1b99fe75e5ca97ca9dd7d4d792f0fb5f5f6a76b",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000",
		"853c7403937d8b6239569b184eb7993fc5f751aefcea28f2c863858e2d29c50b",
	},
	{
		"1000000000000000000000000000000000000000000000000000000000000000",
		"999999999999999000000000000000000000000000000000000000000000000000000000000000000000298980",
		"b090142078fb1cefe60a7aecdea38adc501ac8736c8a006048d7acd45cbcbb02",
	},
	{
		"345798b9727488d203fc9e2296f4e56d2898a9229321ff15f59cc083b69917dd",
		"002012746c73313320732061702074726166666963202b622936831a795ada09f29e8968ee4c481b92335b86cb294deeef1564704b2001",
		"3399908851588a1360ffdbd63378ef1e437f71247587884a727e3bd3c1cb44ef",
	},
}

func TestHmacMDResult(t *testing.T) {
	//iv, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	for _, test := range hmacMDTestData {
		key, _ := hex.DecodeString(test.key)
		msg, _ := hex.DecodeString(test.msg)
		//wantDigest, _ := hex.DecodeString(test.wantDigest)
		md := new(HmacMD)
		//ipad := HmacPadConstructHelper(key, 0x36)
		//ih1, _ := SHA256Gadget(ipad, iv, false, 0)
		ih1, _ := md.ComputeInnerFirstBlockDigest(key)
		md.CompInnerHash(msg, ih1)
		//opad := HmacPadConstructHelper(key, 0x5c)
		//oh1, _ := SHA256Gadget(opad, iv, false, 0)
		oh1, _ := md.ComputeOuterFirstBlockDigest(key)
		md.CompOuterHashMD(md.inner, oh1)
		gotDigest := md.outer
		hmac := hmac.New(sha256.New, key)
		hmac.Write(msg)
		wantDigest := hmac.Sum(nil)
		if !bytes.Equal(gotDigest, wantDigest) {
			t.Errorf("got = % x, want % x", gotDigest, wantDigest)
		}
	}
}

func TestComputeRemainHMAC(t *testing.T) {
	for _, test := range hmacMDTestData {
		key, _ := hex.DecodeString(test.key)
		msg, _ := hex.DecodeString(test.msg)
		md := new(HmacMD)

		ih1, _ := md.ComputeInnerFirstBlockDigest(key)
		md.ComputeRemainHmac(msg, ih1, key)
		gotDigest := md.outer
		hmac := hmac.New(sha256.New, key)
		hmac.Write(msg)
		wantDigest := hmac.Sum(nil)
		if !bytes.Equal(gotDigest, wantDigest) {
			t.Errorf("got = % x, want % x", gotDigest, wantDigest)
		}
	}
}
