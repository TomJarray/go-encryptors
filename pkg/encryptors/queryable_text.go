package encryptors

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

func Decrypt4QueryableText(cipherBytes []byte, passwordBytes []byte, saltBytes []byte) string {
	key := pbkdf2.Key(passwordBytes, saltBytes, 1024, 32, sha1.New)
	if len(key) != 32 {
		panic(fmt.Sprintf("Unexpected key length (!= 32) '%s' %d", key, len(key)))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(cipherBytes) < aes.BlockSize {
		panic("ciphertext too short")
	}

	iv := make([]byte, 16)
	plainText := make([]byte, len(cipherBytes))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainText, cipherBytes)
	return strings.Trim(string(plainText), "\b")
}

func Encrypt4QueryableText(plainBytes []byte, passwordBytes []byte, saltBytes []byte) string {
	key := pbkdf2.Key(passwordBytes, saltBytes, 1024, 32, sha1.New)
	if len(key) != 32 {
		panic(fmt.Sprintf("Unexpected key length (!= 32) '%s' %d", key, len(key)))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	plainBytes = __pkcs7Padding(plainBytes, block.BlockSize())

	if len(plainBytes) < aes.BlockSize {
		panic("plainBytes too short")
	}

	iv := make([]byte, 16)
	cipherBytes := make([]byte, len(plainBytes))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherBytes, plainBytes)

	return hex.EncodeToString(cipherBytes)
}
