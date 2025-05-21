package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserDto struct {
	Name           string    `bson:"name" json:"name"`
	Email          string    `bson:"email" json:"email"`
	Password       string    `bson:"password" json:"password,omitempty"`
	Dob            time.Time `bson:"dob,omitempty" json:"dob,omitempty"`
	Gender         string    `bson:"gender,omitempty" json:"gender,omitempty"`
	CreatedAt      time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time `bson:"updated_at" json:"updated_at"`
	Verified       bool      `bson:"verified" json:"verified"`
	OTP            string    `bson:"otp,omitempty" json:"otp"`
	Votp           string    `bson:"votp,omitempty" json:"votp"`
	LoginOtp       string    `bson:"loginOtp,omitempty" json:"login"`
	IsTwoFactor    bool      `bson:"isTwoFactor, omitempty" json:"isTwoFactor"`
	ExpireLoginOtp time.Time `bson:"expireLoginOtp" json:"expireLoginOtp"`
	Role           string    `bson:"role" json:"role"`
}

type Response struct {
	Message string `json:"message"`
}

type LoginDto struct {
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
}
type RegisterResponse struct {
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Dob       time.Time `json:"dob,omitempty"`
	Gender    string    `json:"gender,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Claims struct {
	Userid string `json:"userid"`
	jwt.RegisteredClaims
}
