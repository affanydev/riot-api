package service

type Signer interface {
	Sign(data map[string]interface{}) (string, error)
	Verify(data map[string]interface{}, signature string) (bool, error)
}
