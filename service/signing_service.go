package service

import (
	"riot-api/tools"
)

func SignPayload(signer tools.Signer, data map[string]interface{}) (string, error) {
	return signer.Sign(data)
}

func VerifySignature(signer tools.Signer, data map[string]interface{}, providedSignature string) bool {
	verified, err := signer.Verify(data, providedSignature)
	if verified && err == nil {
		return true
	}
	return false
}
