package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

func verifyEmail(s1 string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var user1 UserDto
	cursor, _ := collection.Find(ctx, bson.M{})
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		cursor.Decode(&user1)
		if s1 == user1.Email {
			return true
		}
	}
	return false
}

func register(w http.ResponseWriter, r *http.Request) {
	fmt.Println("register")
	w.Header().Set("Content-Type", "application/json")

	var user UserDto
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if r.Body == nil {
		//status code
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "please provide data"})
		return
	}

	json.NewDecoder(r.Body).Decode(&user)

	if verifyEmail(user.Email) {
		w.WriteHeader(http.StatusConflict) // user already exist
		json.NewEncoder(w).Encode(Response{Message: "user already exist"})
		return
	}
	res, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(res)
	result, _ := collection.InsertOne(ctx, user)
	fmt.Println(result.InsertedID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)

}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var tempUser LoginDto
	json.NewDecoder(r.Body).Decode(&tempUser)
	var user UserDto
	cursor, _ := collection.Find(ctx, bson.M{})
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {

		cursor.Decode(&user)

		if user.Email == tempUser.Email {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tempUser.Password))

			if err == nil {
				//login success status code
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(Response{Message: "Login success"})
				return
			}
		}

	}
	w.WriteHeader(http.StatusUnauthorized) // user not found

	json.NewEncoder(w).Encode(Response{Message: "user credential did not match"})

}
