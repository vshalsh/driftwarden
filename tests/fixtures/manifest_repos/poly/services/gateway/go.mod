module github.com/example/gateway

go 1.22

require github.com/gin-gonic/gin v1.9.1

require (
	github.com/redis/go-redis/v9 v9.5.1
	google.golang.org/grpc v1.63.2
	golang.org/x/net v0.24.0 // indirect
)

replace github.com/example/shared => ../shared

exclude (
	google.golang.org/grpc v1.60.0
)
