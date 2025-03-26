package tools

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Base64Encryptor struct{}

func NewBase64Encryptor() *Base64Encryptor {
	return &Base64Encryptor{}
}

func (e *Base64Encryptor) Encrypt(data map[string]interface{}) (map[string]interface{}, error) {
	encryptedData := make(map[string]interface{})

	for key, value := range data {
		jsonData, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data")
		}

		encryptedData[key] = base64.StdEncoding.EncodeToString(jsonData)
	}
	return encryptedData, nil
}

func (e *Base64Encryptor) Decrypt(data map[string]interface{}) (map[string]interface{}, error) {
	decryptedData := make(map[string]interface{})

	for key, value := range data {
		if str, ok := value.(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(str)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt data")
			}

			var jsonData interface{}
			err = json.Unmarshal(decoded, &jsonData)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt data")
			} else {

				decryptedData[key] = jsonData
			}

		} else {
			return nil, fmt.Errorf("values must be string")
		}
	}
	return decryptedData, nil
}
