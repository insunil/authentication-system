package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	user.UpdatedAt = time.Now()

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
	user.Verified = false
	user.OTP = otpGenerator()
	result, _ := collection.InsertOne(ctx, user)
	fmt.Println(result.InsertedID)
	w.WriteHeader(http.StatusCreated)
	// for the response we will not send the password

	var registerResponse RegisterResponse
	registerResponse.Name = user.Name
	registerResponse.Email = user.Email
	registerResponse.Dob = user.Dob
	registerResponse.Gender = user.Gender
	registerResponse.CreatedAt = user.CreatedAt
	registerResponse.UpdatedAt = user.UpdatedAt
	json.NewEncoder(w).Encode(registerResponse)

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

		if user.Email == tempUser.Email && user.Verified {
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

func updateUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("update")
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	nid := params["id"]
	objectId, _ := primitive.ObjectIDFromHex(nid)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var updateUser struct {
		Name   string    `bson:"name,omitempty" json:"name,omitempty"`
		DOB    time.Time `bson:"dob,omitempty" json:"dob,omitempty"`
		Gender string    `bson:"gender,omitempty" json:"gender,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&updateUser)

	filter := bson.M{"_id": objectId}
	update := bson.M{"$set": bson.M{"name": updateUser.Name, "dob": updateUser.DOB, "Gender": updateUser.Gender}}

	res, _ := collection.UpdateOne(ctx, filter, update)
	if res.MatchedCount == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "user not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "user updated successfully"})

}

func getUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("getting")
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	nid := params["id"]
	objectId, _ := primitive.ObjectIDFromHex(nid)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var user UserDto
	err := collection.FindOne(ctx, bson.M{"_id": objectId}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "user not found"})
		return
	}
	w.WriteHeader(http.StatusOK)
	user.Password = "" // remove password from response
	json.NewEncoder(w).Encode(user)

}

func changePassword(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Change password")
	w.Header().Set("Content-Type", "application/json")
	//get object id
	params := mux.Vars(r)
	idParams := params["id"]

	objectid, _ := primitive.ObjectIDFromHex(idParams)

	var tempUser struct {
		OldPassword string `bson:"oldPassword,omitempty" json:"oldPassword,omitempty"`
		NewPassword string `bson:"newPassword,omitempty" json:"newPassword,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&tempUser)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var user UserDto
	err := collection.FindOne(ctx, bson.M{"_id": objectid}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "user not found"})
		return
	}
	// check if old password is correct
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tempUser.OldPassword))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "old password is incorrect"})
		return
	}
	// password validation
	if !ValidatePassword(tempUser.NewPassword) {
		fmt.Println(tempUser.NewPassword)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Password must be between 8 and 20 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character."})
		return
	}
	// decrypt password
	data, _ := bcrypt.GenerateFromPassword([]byte(tempUser.NewPassword), bcrypt.DefaultCost)
	collection.UpdateOne(ctx, bson.M{"_id": objectid}, bson.M{"$set": bson.M{"password": string(data), "updated_at": time.Now()}})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "password changed successfully"})
}

func forgotPassword(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Forget password")
	w.Header().Set("Content-Type", "application/json")
	var tempData struct {
		Email string `bson:"email,omitempty" json:"email,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&tempData)
	// validate email
	_, err := mail.ParseAddress(tempData.Email)
	if err != nil {

		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Invalid email format"})
		return
	}
	// check if email exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// to store only object id from user(it contain lot of field)
	var user struct {
		Id primitive.ObjectID `bson:"_id" json:"_id"`
	}
	result := collection.FindOne(ctx, bson.M{"email": tempData.Email})

	errore := result.Decode(&user)
	if errore != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "user not found"})
		return
	}

	// generate otp and send mail
	otp := otpGenerator()
	// update otp in database in votp field
	collection.UpdateOne(ctx, bson.M{"email": tempData.Email}, bson.M{"$set": bson.M{"votp": otp}})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "otp sent successfully" + "object id is " + user.Id.Hex()})

}
func restPassword(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Reset password")
	w.Header().Set("Content-Type", "application/json")
	//get object id
	params := mux.Vars(r)
	idParams := params["id"]

	objectid, _ := primitive.ObjectIDFromHex(idParams)

	var tempUser struct {
		OTP         string `bson:"otp,omitempty" json:"otp,omitempty"`
		NewPassword string `bson:"newPassword,omitempty" json:"newPassword,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&tempUser)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var user UserDto
	err := collection.FindOne(ctx, bson.M{"_id": objectid}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "user not found"})
		return
	}
	fmt.Println(user.Votp, tempUser.OTP, user.Name)
	if user.Votp != tempUser.OTP {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "otp is incorrect"})
		return
	}
	// password validation
	if !ValidatePassword(tempUser.NewPassword) {
		fmt.Println(tempUser.NewPassword)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Password must be between 8 and 20 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character."})
		return
	}
	// decrypt password
	data, _ := bcrypt.GenerateFromPassword([]byte(tempUser.NewPassword), bcrypt.DefaultCost)
	collection.UpdateOne(ctx, bson.M{"_id": objectid}, bson.M{"$set": bson.M{"password": string(data), "updated_at": time.Now()}})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "password changed successfully"})
}

func otpGenerator() string {

	a := strconv.Itoa(rand.Intn(9))
	b := strconv.Itoa(rand.Intn(9))
	c := strconv.Itoa(rand.Intn(9))
	d := strconv.Itoa(rand.Intn(9))
	otp := a + b + c + d

	message := []byte("Subject:Hello from Go\r\n\r\n Your verified otp for authentication is " + otp)

	auth := smtp.PlainAuth("", "insunilmahto@gmail.com", "ivqt uqto vadl acvz", "smtp.gmail.com")
	err := smtp.SendMail("smtp.gmail.com"+":"+"587", auth, "insunilmahto@gmail.com", []string{"insunilmahto@gmail.com"}, message)
	if err != nil {
		fmt.Println("email did not send successfully")
	} else {
		fmt.Println("email sent successfully")
	}
	return otp
}

// verify otp with otp and id
func verifyOtp(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Verify otp")
	w.Header().Set("Content-Type", "application/json")
	//get object id
	params := mux.Vars(r)
	idParams := params["id"]

	objectid, _ := primitive.ObjectIDFromHex(idParams)

	var tempUser struct {
		OTP string `bson:"otp,omitempty" json:"otp,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&tempUser)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var user UserDto
	err := collection.FindOne(ctx, bson.M{"_id": objectid}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "user not found"})
		return
	}
	if user.OTP != tempUser.OTP {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "otp is incorrect"})
		return
	}
	// update user verified to true
	collection.UpdateOne(ctx, bson.M{"_id": objectid}, bson.M{"$set": bson.M{"verified": true}})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "otp verified successfully"})
}
