package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"sentinel/internal/app"
	"sentinel/internal/httpapi"
)

func main() {
	root := flag.String("root", "", "project root containing public/ and datasets/")
	flag.Parse()
	config, err := app.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	if *root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		*root = cwd
	}
	absolute, err := filepath.Abs(*root)
	if err != nil {
		log.Fatal(err)
	}
	service := app.New(config)
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)
	log.Printf("Sentinel Go MVP %s running at http://%s", app.Version, address)
	if err := http.ListenAndServe(address, httpapi.New(service, absolute)); err != nil {
		log.Fatal(err)
	}
}
