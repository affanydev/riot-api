package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

type AESEncryptor struct {
	key []byte
}

func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	return &AESEncryptor{key: key}, nil
}

func (e *AESEncryptor) Encrypt(data map[string]interface{}) (map[string]interface{}, error) {
	encryptedData := make(map[string]interface{})

	for key, value := range data {
		jsonData, err := json.Marshal(value)
		if err != nil {
			return nil, errors.New("failed to encrypt data")
		}

		ciphertext, err := e.encryptAES(jsonData)
		if err != nil {
			return nil, err
		}
		encryptedData[key] = ciphertext
	}

	return encryptedData, nil
}

func (e *AESEncryptor) Decrypt(data map[string]interface{}) (map[string]interface{}, error) {
	decryptedData := make(map[string]interface{})

	for key, value := range data {
		if str, ok := value.(string); ok {
			decoded, err := e.decryptAES(str)
			if err != nil {
				return nil, err
			}

			var jsonData interface{}
			err = json.Unmarshal(decoded, &jsonData)
			if err != nil {
				return nil, errors.New("failed to decrypt data")
			}

			decryptedData[key] = jsonData
		} else {
			return nil, errors.New("values must be strings")
		}
	}

	return decryptedData, nil
}

func (e *AESEncryptor) encryptAES(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12) // 12 bytes for GCM nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (e *AESEncryptor) decryptAES(ciphertext string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(decoded) < 12 {
		return nil, errors.New("invalid ciphertext")
	}

	nonce := decoded[:12]
	encryptedText := decoded[12:]

	plaintext, err := gcm.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
