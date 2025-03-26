package service

func SignPayload(signer Signer, data map[string]interface{}) (string, error) {
	return signer.Sign(data)
}

func VerifySignature(signer Signer, data map[string]interface{}, providedSignature string) bool {
	verified, err := signer.Verify(data, providedSignature)
	if verified && err == nil {
		return true
	}
	return false
}
