package tools

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

const AES_256_GCM_ENCRYPTION_KEY = "mpIZXC9uEsTe7f9g1fXXMspXliOCWNOg"

func TestAESEncryptor_NewAESEncryptor_InvalidKey(t *testing.T) {
	key := []byte("shortkey") // Invalid key length
	_, err := NewAESEncryptor(key)
	if err == nil {
		t.Fatal("expected error for invalid key length, but got none")
	}
}

func TestAESEncryptor_Encrypt(t *testing.T) {
	// Prepare
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
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

	// Check: ensure encryptedData has AES_256 encoded strings
	for key, value := range encryptedData {
		if _, ok := value.(string); !ok {
			t.Fatalf("expected value of %s to be a AES_256_GCM encoded string, got %v", key, value)
		}
	}
}

func TestAESEncryptor_Decrypt(t *testing.T) {
	// Prepare
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
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

func TestAESEncryptor_Decrypt_InvalidData(t *testing.T) {
	// Prepare
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
	invalidData := map[string]interface{}{
		"key1": "invalidData",
	}

	// Perform
	_, err = encryptor.Decrypt(invalidData)

	// Check
	if err == nil {
		t.Fatal("expected error during decryption of invalid AES_256_GCM, but got none")
	}
}

func TestAESEncryptor_Decrypt_ShortCiphertext(t *testing.T) {
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Providing a short ciphertext
	shortCiphertext := "short"
	_, err = encryptor.decryptAES(shortCiphertext)
	if err == nil {
		t.Fatal("expected error for short ciphertext, but got none")
	}
}

func TestAESEncryptor_Encrypt_LargeData(t *testing.T) {
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Large data
	largeData := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		largeData[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	encryptedData, err := encryptor.Encrypt(largeData)
	if err != nil {
		t.Fatalf("expected no error during encryption, but got %v", err)
	}

	if len(encryptedData) == 0 {
		t.Fatal("expected encrypted data, but got empty map")
	}
}

func TestAESEncryptor_Decrypt_InvalidDataType(t *testing.T) {
	// Prepare
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
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

func TestAESEncryptor_Decryption_EmptyData(t *testing.T) {
	// Prepare
	key := []byte(AES_256_GCM_ENCRYPTION_KEY)
	encryptor, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
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

func TestDecrypt_ErrorCreatingAESCipher(t *testing.T) {

	t.Run("error creating AES cipher", func(t *testing.T) {
		invalidKey := []byte("shortkey")
		encryptor := &AESEncryptor{key: invalidKey}
		ciphertext := "J/a10ovTagsgHo+3LmbMNmy5wDE/7JWiFQTR1gs9Q0IDIFx6iybyyblR"
		plaintext, err := encryptor.decryptAES(ciphertext)
		assert.Error(t, err)
		assert.Nil(t, plaintext)
	})

}
