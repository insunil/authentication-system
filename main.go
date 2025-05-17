package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var collection *mongo.Collection

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Unable to load env variable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	clientOption := options.Client().ApplyURI(os.Getenv("MONGO_URI"))
	client, err := mongo.Connect(ctx, clientOption)
	if err != nil {
		log.Fatal("unable to connect")
	}
	collection = client.Database("auth").Collection("user")
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/auth/login", login).Methods("POST")
	r.HandleFunc("/auth/register", register).Methods("POST")

	r.NotFoundHandler = http.HandlerFunc(notFound)

	fmt.Println("Starting server ...")
	http.ListenAndServe(":4000", r)
}
