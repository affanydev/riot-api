package tools

import (
	"reflect"
	"testing"
)

func normalizeValue(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		// Normalize slice
		normalizedSlice := make([]interface{}, len(v))
		for i, elem := range v {
			normalizedSlice[i] = normalizeValue(elem)
		}
		return normalizedSlice
	case map[string]interface{}:
		// Normalize maps
		normalizedMap := make(map[string]interface{})
		for k, val := range v {
			normalizedMap[k] = normalizeValue(val)
		}
		return normalizedMap
	case int:
		// Convert int to float64 to match JSON decoding behavior
		return float64(v)
	default:
		return v
	}
}

func TestBase64Encryptor_Encrypt(t *testing.T) {
	// Prepare
	encryptor := &Base64Encryptor{}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": 123.123,
		"key4": []interface{}{333, "value4"},
	}

	// Perform
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Check: ensure encryptedData has base64-encoded strings
	for key, value := range encryptedData {
		if _, ok := value.(string); !ok {
			t.Fatalf("expected value of %s to be a base64 encoded string, got %v", key, value)
		}
	}
}

func TestBase64Encryptor_Decrypt(t *testing.T) {
	// Prepare
	encryptor := &Base64Encryptor{}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": 123.123,
		"key4": []interface{}{333, "value4"},
	}

	// Perform encryption
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("expected no error during encryption, but got %v", err)
	}

	// Perform decryption
	decryptedData, err := encryptor.Decrypt(encryptedData)
	if err != nil {
		t.Fatalf("expected no error during decryption, but got %v", err)
	}

	// Check: ensure decrypted data matches the original data

	for key, originalValue := range data {
		decryptedValue, exists := decryptedData[key]
		if !exists {
			t.Fatalf("expected key %s in decrypted data", key)
		}

		normalizedOriginal := normalizeValue(originalValue)
		normalizedDecrypted := normalizeValue(decryptedValue)

		if !reflect.DeepEqual(normalizedOriginal, normalizedDecrypted) {
			t.Fatalf("expected decrypted value for %s to be %v, but got %v", key, normalizedOriginal, normalizedDecrypted)
		}
	}
}

func TestBase64Encryptor_Decrypt_InvalidBase64(t *testing.T) {
	// Prepare
	encryptor := &Base64Encryptor{}
	invalidData := map[string]interface{}{
		"key1": "invalidBase64",
	}

	// Perform
	_, err := encryptor.Decrypt(invalidData)

	// Check
	if err == nil {
		t.Fatal("expected error during decryption of invalid base64, but got none")
	}
}

func TestBase64Encryptor_Decrypt_InvalidDataType(t *testing.T) {
	// Prepare
	encryptor := &Base64Encryptor{}
	data := map[string]interface{}{
		"key1": "value1",
	}

	// Perform encryption
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("expected no error during encryption, but got %v", err)
	}

	// Modify encrypted data to simulate wrong data type
	encryptedData["key1"] = 12345

	// Perform decryption
	_, err = encryptor.Decrypt(encryptedData)

	// Check
	if err == nil {
		t.Fatal("expected error due to incorrect data type in encrypted data, but got none")
	}
}

func TestBase64Encryptor_Decrypt_InvalidData(t *testing.T) {
	// Prepare
	encryptor := &Base64Encryptor{}
	data := map[string]interface{}{
		"key1": "e1wia2V5MVwiOiB2YWx1ZTFcIn0=",
	}

	// Perform decryption
	_, err := encryptor.Decrypt(data)

	// Check
	if err == nil {
		t.Fatal("expected error due to incorrect data type in encrypted data, but got none")
	}
}

func TestBase64Encryptor_Decryption_EmptyData(t *testing.T) {
	// Prepare
	encryptor := &Base64Encryptor{}
	data := map[string]interface{}{}

	// Perform encryption
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("expected no error during encryption, but got %v", err)
	}

	// Perform decryption
	decryptedData, err := encryptor.Decrypt(encryptedData)
	if err != nil {
		t.Fatalf("expected no error during decryption, but got %v", err)
	}

	// Check
	if len(decryptedData) != 0 {
		t.Fatalf("expected decrypted data to be empty, but got %v", decryptedData)
	}
}
