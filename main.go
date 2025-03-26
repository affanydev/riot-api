package main

import (
	"log"
	"os"
	"riot-api/controller"
	"riot-api/tools"

	_ "riot-api/docs"

	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	setupEnv()
	cryptoController := initCryptoController()
	r := setupRouter(cryptoController)
	r.Run(":8022")
}

func setupEnv() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("Error loading .env file")
	}

	if os.Getenv("SIGNING_KEY") == "" {
		log.Fatalf("SIGNING_KEY environment variable is not set")
	}
}

func initCryptoController() *controller.CryptoController {
	signer := tools.NewHMACSigner([]byte(os.Getenv("SIGNING_KEY")))
	encryptor := tools.NewBase64Encryptor()
	return controller.NewCryptoController(signer, encryptor)
}

func setupRouter(cryptoController *controller.CryptoController) *gin.Engine {
	r := gin.Default()
	rateLimiter := tollbooth.NewLimiter(1000, nil)

	r.Use(controller.Cors)
	r.Use(controller.RateLimiter(rateLimiter))

	r.POST("/encrypt", cryptoController.Encrypt)
	r.POST("/decrypt", cryptoController.Decrypt)
	r.POST("/sign", cryptoController.Sign)
	r.POST("/verify", cryptoController.Verify)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	return r
}
