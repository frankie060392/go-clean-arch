package main

import (
	"fmt"
	"log"

	"github.com/frankie060392/golang-gorm-postgres/initializers"
	"github.com/frankie060392/golang-gorm-postgres/models"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("? Could not load environment variables", err)
	}

	initializers.ConnectDB(&config)
}

func main() {
	initializers.DB.AutoMigrate(&models.User{})
	fmt.Println("? Migration complete")
}
