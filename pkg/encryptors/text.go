package encryptors

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

/**
*  Creates a text encryptor that uses "standard" password-based encryption. Encrypted text is hex-encoded
 */

//test001
//6ab2dce780293e3d224221b9dff6bf4ed8c38c46c841f7ec758be76e0e1c4612
//17c10b7073c995b19ae2a42dfb56b1b39eb633b439cfeb83c386dff718a63adb

func Encrypt4Text(plainBytes []byte, passwordBytes []byte, saltBytes []byte) string {
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
		panic("ciphertext too short")
	}

	iv := make([]byte, aes.BlockSize)
	_, errRead := rand.Read(iv)
	if errRead != nil {
		fmt.Println("error:", err)
		panic("Rand Read failed...")
	}
	//plainBytes = plainBytes[aes.BlockSize:]
	//if len(plainBytes)%aes.BlockSize != 0 {
	//	panic("ciphertext is not a multiple of the block size")
	//}

	cipherBytes := make([]byte, len(plainBytes))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherBytes, plainBytes)

	cipherBytes = append(iv, cipherBytes...)

	return hex.EncodeToString(cipherBytes)
}

func Decrypt4Text(cipherBytes []byte, passwordBytes []byte, saltBytes []byte) string {
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
	iv := cipherBytes[:aes.BlockSize]
	cipherBytes = cipherBytes[aes.BlockSize:]
	if len(cipherBytes)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherBytes, cipherBytes)
	return strings.TrimSpace(string(cipherBytes))
}
