package encryptors

import (
	"encoding/hex"
	"testing"
)

var password []byte
var salt []byte

const plainText = "test001"
const cipheredText = "6b0adc094a5b20ef28e9c0de0361355e"

func init() {
	password = []byte("HowTote6T6nP1Jkp")
	salt, _ = hex.DecodeString("89f81e60442389f6")
}

func Test_queryable_text_encrypt(t *testing.T) {

	plainTextBytes := []byte(plainText)
	newCipheredText := Encrypt4QueryableText(plainTextBytes, password, salt)
	if newCipheredText == cipheredText {
		t.Log("success")
	}
}

func Test_queryable_text_decrypt(t *testing.T) {

	cipheredTextBytes, _ := hex.DecodeString(cipheredText)
	newPlainText := Decrypt4QueryableText(cipheredTextBytes, password, salt)
	if newPlainText == plainText {
		t.Log("success")
	}
}
