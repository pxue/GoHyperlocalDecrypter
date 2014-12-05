package decrypt

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

var ADX_ENC_KEY []byte = []byte{0x02, 0xEE, 0xa8, 0x3c, 0x6c, 0x12, 0x11, 0xe1, 0x0b, 0x9f, 0x88, 0x96, 0x6c, 0xee, 0xc3, 0x49, 0x08, 0xeb, 0x94, 0x6f, 0x7e, 0xd6, 0xe4, 0x41, 0xaf, 0x42, 0xb3, 0xc0, 0xf3, 0x21, 0x81, 0x40}
var ADX_INT_KEY []byte = []byte{0xbf, 0xFF, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1, 0xd8, 0xcd, 0x18, 0x62, 0xed, 0x2a, 0x4c, 0xd2, 0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a, 0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92}

const IV_SIZE = 16
const SIGNATURE_SIZE = 4
const BLOCK_SIZE = 20

func AdxHyperlocalDecrypt(encoded []byte) bool {

	plaintext_length := len(encoded) - IV_SIZE - SIGNATURE_SIZE
	cipherEnd := IV_SIZE + plaintext_length
	iv := encoded[0:IV_SIZE]

	mac := hmac.New(sha1.New, ADX_ENC_KEY)
	mac.Write(iv)
	pad := mac.Sum(nil)

	plaintext := make([]byte, plaintext_length)
	ivCounter := true
	for cipherBegin, plainBegin := IV_SIZE, 0; cipherBegin < cipherEnd; {
		for i := 0; i < BLOCK_SIZE && cipherBegin != cipherEnd; i, plainBegin, cipherBegin = i+1, plainBegin+1, cipherBegin+1 {
			plaintext[plainBegin] = byte(encoded[cipherBegin] ^ pad[i])
		}

		if !ivCounter {
			index := len(iv) - 1
			iv[index]++
			ivCounter = iv[index] == 0
		}

		if ivCounter {
			ivCounter = false
			iv = append(iv, 0)
		}

		mac.Reset()
		mac.Write(iv)
		pad = mac.Sum(nil)
	}

	// integrity hash
	sigMac := hmac.New(sha1.New, ADX_INT_KEY)
	sigMac.Write(plaintext)
	sigMac.Write(encoded[0:IV_SIZE])
	messageSig := sigMac.Sum(nil)

	expectedSig := encoded[IV_SIZE+plaintext_length:]
	fmt.Println(messageSig[:SIGNATURE_SIZE], expectedSig)

	return hmac.Equal(messageSig, expectedSig)
}
