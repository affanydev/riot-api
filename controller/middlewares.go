package controller

import (
	"net/http"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/gin-gonic/gin"
)

func Cors(c *gin.Context) {

	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "*")
	c.Header("Access-Control-Allow-Headers", "*")
	c.Header("Content-Type", "application/json")

	if c.Request.Method != "OPTIONS" {
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusOK)
	}
}

func RateLimiter(limiter *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {

		clientIP := c.ClientIP()
		limiterKey := "IP-" + clientIP

		httpErr := tollbooth.LimitByKeys(limiter, []string{limiterKey})
		if httpErr != nil {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too Many Request, please try later",
			})
			c.Abort()
			return
		}

		c.Next()
	}

}
