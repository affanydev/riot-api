package main

import (
	"log"
	"riot-api/controller"

	_ "riot-api/docs"

	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	if err := controller.Init(); err != nil {
		log.Fatalf("Failed to initialize controller: %v", err)
	}

	r := gin.Default()
	rateLimiter := tollbooth.NewLimiter(10, nil) // limit user (IP) at 10 req/sec
	r.Use(controller.Cors)
	r.Use(controller.RateLimiter(rateLimiter))

	// Routes
	r.POST("/encrypt", controller.Encrypt)
	r.POST("/decrypt", controller.Decrypt)
	r.POST("/sign", controller.Sign)
	r.POST("/verify", controller.Verify)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	r.Run(":8022")
}
