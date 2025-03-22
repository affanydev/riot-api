package tools

type Encryptor interface {
	Encrypt(data map[string]interface{}) (map[string]interface{}, error)
	Decrypt(data map[string]interface{}) (map[string]interface{}, error)
}
