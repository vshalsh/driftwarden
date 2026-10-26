package main

import (
	"fmt"
	"net/http"

	"example.com/shop/internal/store"
	db "example.com/shop/pkg/db"
	_ "github.com/lib/pq"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"example.com/lib/util"
	"example.com/shop/missing"
	// "commented/out"
)

var doc = `
import "fake/inside/raw"
`

func main() { fmt.Println(http.StatusOK, store.X, db.Y, s3.Z, util.W, doc) }
