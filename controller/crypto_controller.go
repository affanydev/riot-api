package controller

import (
	"net/http"
	"riot-api/service"

	"github.com/gin-gonic/gin"
)

// VerifyRequest defines the struct for the signature verification request.
// @Description This is used for the request body of /verify
type VerifyRequest struct {
	Signature string                 `json:"signature" binding:"required"`
	Data      map[string]interface{} `json:"data" binding:"required"`
}

type CryptoController struct {
	signer    service.Signer
	encryptor service.Encryptor
}

func NewCryptoController(signer service.Signer, encryptor service.Encryptor) *CryptoController {
	return &CryptoController{
		signer:    signer,
		encryptor: encryptor,
	}
}

// Encrypt godoc
// @Summary Encrypts the given data
// @Description Encrypts the values of the object at a depth of 1 using Base64 encoding.
// @Tags Encryption
// @Accept  json
// @Produce  json
// @Param data body map[string]interface{} true "Data to encrypt"
// @Success 200 {object} map[string]string "Encrypted data"
// @Failure 400 {string} string "Invalid JSON"
// @Failure 500 {string} string "Internal Server Error"
// @Router /encrypt [post]
func (cc *CryptoController) Encrypt(c *gin.Context) {
	var payload map[string]interface{}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	encryptedData, err := service.EncryptPayload(cc.encryptor, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, encryptedData)
}

// Decrypt godoc
// @Summary Decrypts the given data
// @Description Decrypts the Base64 encoded values in the object at depth 1.
// @Tags Encryption
// @Accept  json
// @Produce  json
// @Param data body map[string]interface{} true "Data to decrypt"
// @Success 200 {object} map[string]interface{} "Decrypted data"
// @Failure 400 {string} string "Invalid JSON"
// @Failure 500 {string} string "Internal Server Error"
// @Router /decrypt [post]
func (cc *CryptoController) Decrypt(c *gin.Context) {
	var payload map[string]interface{}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	decryptedData, err := service.DecryptPayload(cc.encryptor, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, decryptedData)
}

// Sign godoc
// @Summary Generates a cryptographic signature for the given data
// @Description Computes an HMAC signature using the provided data and a secret key.
// @Tags Signing
// @Accept  json
// @Produce  json
// @Param data body map[string]interface{} true "Data to sign"
// @Success 200 {object} map[string]string "Signature"
// @Failure 400 {string} string "Invalid JSON"
// @Failure 500 {string} string "Internal Server Error"
// @Router /sign [post]
func (cc *CryptoController) Sign(c *gin.Context) {
	var payload map[string]interface{}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	signature, err := service.SignPayload(cc.signer, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"signature": signature})
}

// Verify godoc
// @Summary Verifies the provided signature for the given data
// @Description Verifies if the provided HMAC signature matches the computed signature for the data.
// @Tags Signing
// @Accept  json
// @Produce  json
// @Param request body controller.VerifyRequest true "Signature verification request"
// @Success 204 "Signature is valid"
// @Failure 400 {string} string "Invalid JSON or Invalid signature"
// @Router /verify [post]
func (cc *CryptoController) Verify(c *gin.Context) {
	var request VerifyRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	verified := service.VerifySignature(cc.signer, request.Data, request.Signature)

	if verified {
		c.Status(http.StatusNoContent)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
	}
}
