package tools

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const SIGNING_KEY_TEST_1 = "7b03af03735a58b17fa00804dbf683b64ab30f29d2684893fc33759ae19f02c4"
const SIGNING_KEY_TEST_2 = "BDCF65F17D9AFB2949658D21FD41F4833C4E0CE80E25720079422A58D6FD60F8"

func TestMain(m *testing.M) {
	// Before tests

	// Run tests
	code := m.Run()

	// After tests
	os.Exit(code)
}

func TestHMACSigner_Sign(t *testing.T) {
	// Prepare
	secretKey := []byte(SIGNING_KEY_TEST_1)
	signer := &HMACSigner{SecretKey: secretKey}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	// Perform
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Check
	if signature == "" {
		t.Fatal("expected signature to be non-empty")
	}
}

func TestHMACSigner_Sign_InvalidJSON(t *testing.T) {
	// Prepare
	secretKey := []byte(SIGNING_KEY_TEST_1)
	signer := &HMACSigner{SecretKey: secretKey}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": func() {},
	}

	// Perform
	signature, err := signer.Sign(data)
	if err == nil {
		t.Fatalf("expected error, but got error nil")
	}

	// Check
	assert.Equal(t, err.Error(), "failed signing")
	assert.Equal(t, signature, "")
}
func TestHMACSigner_Verify_Positive(t *testing.T) {
	// Prepare
	secretKey := []byte(SIGNING_KEY_TEST_1)
	signer := &HMACSigner{SecretKey: secretKey}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	// Perform
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Positive validation: Verify with the correct signature
	isValid, err := signer.Verify(data, signature)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
	if !isValid {
		t.Fatal("expected signature to be valid")
	}
}

func TestHMACSigner_Verify_Wrong_Data(t *testing.T) {
	// Prepare
	secretKey := []byte(SIGNING_KEY_TEST_1)
	signer := &HMACSigner{SecretKey: secretKey}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	// Perform
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Check
	alteredData := map[string]interface{}{
		"key1": "value1",
		"key2": "wrongValue",
	}

	isValid, err := signer.Verify(alteredData, signature)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
	if isValid {
		t.Fatal("expected signature to be invalid for altered data")
	}

}

func TestHMACSigner_Verify_Wrong_Signature(t *testing.T) {
	// Prepare
	secretKey1 := []byte(SIGNING_KEY_TEST_1)
	secretKey2 := []byte(SIGNING_KEY_TEST_2)
	signer1 := &HMACSigner{SecretKey: secretKey1}
	signer2 := &HMACSigner{SecretKey: secretKey2}
	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	// Perform
	signature2, err := signer2.Sign(data)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	// Check
	isValid, err := signer1.Verify(data, signature2)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
	if isValid {
		t.Fatal("expected signature to be invalid for altered signature")
	}
}

func TestHMACSigner_Verify_InvalidJSON(t *testing.T) {
	// Prepare
	secretKey1 := []byte(SIGNING_KEY_TEST_1)
	signer1 := &HMACSigner{SecretKey: secretKey1}
	signature1 := "data-for-signature-1"
	data := map[string]interface{}{
		"key1": "value1",
		"key2": func() {},
	}

	// Perform
	isValid, err := signer1.Verify(data, signature1)

	// Check
	assert.Equal(t, err.Error(), "failed verifying")
	assert.Equal(t, isValid, false)
}
