package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"sentinel/internal/app"
	"sentinel/internal/httpapi"
	"sentinel/internal/store"
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
	repository := store.Repository(store.NewMemory())
	if config.DatabaseURL != "" {
		repository, err = store.NewPostgres(context.Background(), config.DatabaseURL, store.PostgresOptions{
			MaxOpenConnections: config.DatabaseMaxOpen,
			MaxIdleConnections: config.DatabaseMaxIdle,
			OperationTimeout:   config.DatabaseTimeout,
		})
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("WARNING: in-memory storage explicitly enabled; events and alerts will not survive restart")
	}
	defer repository.Close()
	service := app.NewWithStore(config, repository)
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)
	summary := service.Summary()
	log.Printf("repository ready storage=%s events=%d behaviors=%d alerts=%d incidents=%d", repository.Name(), summary["events"], summary["behaviors"], summary["alerts"], summary["incidents"])
	log.Printf("Sentinel Go MVP %s running at http://%s", app.Version, address)
	if err := http.ListenAndServe(address, httpapi.New(service, absolute)); err != nil {
		log.Fatal(err)
	}
}
