package controller

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// Data
var ValidJsonPayload = map[string]interface{}{"key1": "value1"}
var EncryptedValidJsonPayload = map[string]interface{}{"key1": "InZhbHVlMSI="}
var SignatureValidJsonPayload = "cJPPgZbzRuRhQNR8loSgf1TEJgmIuk68yu1P+kWv1C4="
var SigningKeyTest = "7b03af03735a58b17fa00804dbf683b64ab30f29d2684893fc33759ae19f02c4"

var InvalidJsonPayload = "{\"key1\": value1\"}"
var InvalidEncryptedJsonPayload = "{\"key1\": InZhbHVlMSI=\"}"

func setUpRouter() *gin.Engine {
	// increase limiter to run tests
	rateLimiter := tollbooth.NewLimiter(1000, nil)
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.Use(Cors)
	router.Use(RateLimiter(rateLimiter))
	return router
}

func TestMain(m *testing.M) {
	// Before tests
	os.Setenv("SIGNING_KEY", SigningKeyTest)
	if err := Init(); err != nil {
		log.Fatalf("Failed to initialize controller: %v", err)
	}

	// Run tests
	code := m.Run()

	// After tests
	os.Exit(code)
}

func TestEncrypt(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/encrypt", Encrypt)

	jsonValue, _ := json.Marshal(ValidJsonPayload)

	req, _ := http.NewRequest(http.MethodPost, "/encrypt", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, EncryptedValidJsonPayload["key1"], response["key1"])
}

func TestEncrypt_InvalidJSON(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/encrypt", Encrypt)

	req, _ := http.NewRequest(http.MethodPost, "/encrypt", bytes.NewBuffer([]byte(InvalidJsonPayload)))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Invalid JSON", response["error"])

}

func TestDecrypt(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/decrypt", Decrypt)

	jsonValue, _ := json.Marshal(EncryptedValidJsonPayload)

	req, _ := http.NewRequest(http.MethodPost, "/decrypt", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, ValidJsonPayload["key1"], response["key1"])
}

func TestDecrypt_InvalidJSON(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/decrypt", Decrypt)

	req, _ := http.NewRequest(http.MethodPost, "/decrypt", bytes.NewBuffer([]byte(InvalidEncryptedJsonPayload)))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Invalid JSON", response["error"])
}

func TestDecrypt_InvalidData(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/decrypt", Decrypt)

	req, _ := http.NewRequest(http.MethodPost, "/decrypt", bytes.NewBuffer([]byte("{\"key1\": \"invalidBase64\"}")))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

}

func TestSign(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/sign", Sign)

	jsonValue, _ := json.Marshal(ValidJsonPayload)

	req, _ := http.NewRequest(http.MethodPost, "/sign", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, SignatureValidJsonPayload, response["signature"])
}

func TestSign_InvalidJSON(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/sign", Sign)

	req, _ := http.NewRequest(http.MethodPost, "/sign", bytes.NewBuffer([]byte(InvalidJsonPayload)))
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Invalid JSON", response["error"])

}

func TestVerify_ValidSignature(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/verify", Verify)

	payload := map[string]interface{}{
		"signature": SignatureValidJsonPayload,
		"data":      ValidJsonPayload,
	}
	jsonValue, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestVerify_InvalidSignature(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/verify", Verify)

	payload := map[string]interface{}{
		"signature": "wrong-signature",
		"data":      ValidJsonPayload,
	}
	jsonValue, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Invalid signature", response["error"])
}

func TestVerify_InvalidJSON(t *testing.T) {
	// Prepare
	router := setUpRouter()
	router.POST("/verify", Verify)

	payload := map[string]interface{}{
		"signature": "wrong-signature",
		"data":      InvalidJsonPayload,
	}
	jsonValue, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Invalid JSON", response["error"])
}
