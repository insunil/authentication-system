package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
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
	// password validation
	if !ValidatePassword(user.Password) {
		fmt.Println(user.Password)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Password must be between 8 and 20 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character."})
		return
	}
	//

	if verifyEmail(user.Email) {
		w.WriteHeader(http.StatusConflict) // user already exist
		json.NewEncoder(w).Encode(Response{Message: "user already exist"})
		return
	}
	res, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(res)
	user.CreatedAt = time.Now()
	// check if dob is empty
	if user.Dob.IsZero() {
		fmt.Println("dob is empty")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Invalid date of birth"})
		return
	}
	// if not empty
	if !user.Dob.IsZero() {
		age := time.Now().Year() - user.Dob.Year()
		if time.Now().YearDay() < user.Dob.YearDay() {
			age--
		}
		if age < 18 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(Response{Message: "user must be 18 years or older"})
			return
		}
	}
	//

	result, _ := collection.InsertOne(ctx, user)
	fmt.Println(result.InsertedID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)

}

func ValidatePassword(password string) bool {
	if len(password) < 8 {
		fmt.Println("password is less than 8", len(password))
		return false
	}

	if len(password) > 20 {
		fmt.Println("password is greater than 20", len(password))
		return false
	}

	if match, _ := regexp.MatchString(`[A-Z]`, password); !match {
		fmt.Println("password must contain at least one uppercase letter")
		return false
	}

	if match, _ := regexp.MatchString(`[a-z]`, password); !match {
		fmt.Println("password must contain at least one lowercase letter")
		return false
	}

	if match, _ := regexp.MatchString(`[0-9]`, password); !match {
		fmt.Println("password must contain at least one digit")
		return false
	}

	if match, _ := regexp.MatchString(`[^a-zA-Z0-9]`, password); !match {
		fmt.Println("password must contain at least one special character")
		return false
	}

	return true
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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

func notFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: "not found"})
}
