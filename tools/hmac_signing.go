package tools

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type HMACSigner struct {
	SecretKey []byte
}

func (s *HMACSigner) Sign(data map[string]interface{}) (string, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed signing")
	}

	h := hmac.New(sha256.New, s.SecretKey)
	h.Write(dataBytes)

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature, nil
}

func (s *HMACSigner) Verify(data map[string]interface{}, signature string) (bool, error) {
	expectedSignature, err := s.Sign(data)
	if err != nil {
		return false, fmt.Errorf("failed verifying")
	}

	return expectedSignature == signature, nil
}
