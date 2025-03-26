package service

func EncryptPayload(encryptor Encryptor, data map[string]interface{}) (map[string]interface{}, error) {
	return encryptor.Encrypt(data)
}

func DecryptPayload(encryptor Encryptor, data map[string]interface{}) (map[string]interface{}, error) {
	return encryptor.Decrypt(data)
}
