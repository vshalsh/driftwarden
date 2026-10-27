package main

import (
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/gin-gonic/gin"

	"example.com/gosvc/internal/events"
)

func main() {
	_, _ = config.LoadDefaultConfig(nil)
	events.Publish()
	gin.Default().Run()
}
