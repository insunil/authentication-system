package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var collection *mongo.Collection
var logger *slog.Logger

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

	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

}
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/auth/login", login).Methods("POST")
	r.HandleFunc("/auth/register", register).Methods("POST")
	r.HandleFunc("/user", updateUser).Methods("PUT")
	r.HandleFunc("/user", getUser).Methods("GET")
	r.HandleFunc("/auth/change-password", changePassword).Methods("PUT")
	r.HandleFunc("/auth/forgot-password", forgotPassword).Methods("POST")
	r.HandleFunc("/auth/verify-emailotp/{id}", verifyEmailOtp).Methods("PUT")
	r.HandleFunc("/auth/reset-password/{id}", resetPassword).Methods("POST")
	r.HandleFunc("/auth/verify-login/{id}", loginWithOtp).Methods("POST")
	r.NotFoundHandler = http.HandlerFunc(notFound)

	logger.Info("Starting server ...")

	http.ListenAndServe(":4000", r)
}
