package encryptors

import (
	"encoding/hex"
	"testing"
)

var password []byte
var salt []byte

const plainText = "test001"
const cipheredText = "12558c9235c712d2213956b0a85c8801"
const passwordText = "HowTote6T6nP1Jkp"
const saltText = "89f81e60442389f6"

func init() {
	password = []byte(passwordText)
	salt, _ = hex.DecodeString(saltText)
}

func Test_queryable_text_encrypt(t *testing.T) {

	plainTextBytes := []byte(plainText)
	newCipheredText := Encrypt4QueryableText(plainTextBytes, password, salt)
	//fmt.Printf("newCipheredText is: %s dd\n", newCipheredText)
	if newCipheredText == cipheredText {
		t.Log("success")
	} else {
		t.Fail()
	}
}

func Test_queryable_text_decrypt(t *testing.T) {

	cipheredTextBytes, _ := hex.DecodeString(cipheredText)
	newPlainText := Decrypt4QueryableText(cipheredTextBytes, password, salt)
	//log.Printf("newPlainText is: %s ddd\n", newPlainText)
	if newPlainText == plainText {
		t.Log("success")
	} else {
		t.Fail()
	}
}
