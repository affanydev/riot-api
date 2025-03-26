package controller

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"riot-api/tools"
	"testing"

	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestOptionsRequest(t *testing.T) {
	// Prepare
	router := setUpRouter()

	req, _ := http.NewRequest(http.MethodOptions, "/encrypt", nil)
	req.Header.Set("Content-Type", "application/json")

	// Perform
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

}

func TestRateLimiter(t *testing.T) {
	// Prepare
	rateLimiter := tollbooth.NewLimiter(1, nil)
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.Use(Cors)
	router.Use(RateLimiter(rateLimiter))
	signer := tools.NewHMACSigner([]byte(os.Getenv("SIGNING_KEY")))
	encryptor := tools.NewBase64Encryptor()
	cryptoController := NewCryptoController(signer, encryptor)

	router.POST("/encrypt", cryptoController.Encrypt)

	// should pass
	w := performRequest(router, "POST", "/encrypt", bytes.NewBuffer([]byte("{\"key1\": \"value1\"}")))
	assert.Equal(t, http.StatusOK, w.Code)

	// the second should fail
	w = performRequest(router, "POST", "/encrypt", bytes.NewBuffer([]byte("{\"key1\": \"value1\"}")))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func performRequest(r http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
