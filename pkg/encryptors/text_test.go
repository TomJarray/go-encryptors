package encryptors

import (
	"encoding/hex"
	"fmt"
	"testing"
)

const plainText2 = "test001"
const cipheredText2 = "3531637c69b402ff589eee0a09be5aa6975ed449230620f72dac7b8e9dce4652"

func init() {
	password = []byte(passwordText)
	salt, _ = hex.DecodeString(saltText)
}

func Test_text_decrypt(t *testing.T) {

	cipheredTextBytes, _ := hex.DecodeString(cipheredText2)
	newPlainText := Decrypt4Text(cipheredTextBytes, password, salt)
	//fmt.Printf("newPlainText is: %s ddd\n\n", newPlainText)
	if newPlainText == plainText2 {
		t.Log("success")
	} else {
		t.Fail()
	}
}

func Test_text_encrypt(t *testing.T) {

	plainTextBytes := []byte(plainText2)
	newCipheredText := Encrypt4Text(plainTextBytes, password, salt)

	fmt.Printf("newCipheredText is: %s ddd\n\n", newCipheredText)

	// It used the method: Decrypt4Text to verify the method: Encrypt4Text
	cipheredTextBytes, _ := hex.DecodeString(newCipheredText)
	newPlainText := Decrypt4Text(cipheredTextBytes, password, salt)

	if newPlainText == plainText2 {
		t.Log("success")
	} else {
		fmt.Printf("Test failed, actual result: %s\n", newCipheredText)
		t.Fail()
	}
}
