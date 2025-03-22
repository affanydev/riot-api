package service

import (
	"riot-api/tools"
)

func EncryptPayload(encryptor tools.Encryptor, data map[string]interface{}) (map[string]interface{}, error) {
	return encryptor.Encrypt(data)
}

func DecryptPayload(encryptor tools.Encryptor, data map[string]interface{}) (map[string]interface{}, error) {
	return encryptor.Decrypt(data)
}
