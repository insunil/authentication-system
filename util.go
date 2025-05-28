package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserDto struct {
	Name               string    `bson:"name" json:"name"`
	Email              string    `bson:"email" json:"email"`
	Password           string    `bson:"password" json:"password,omitempty"`
	Dob                time.Time `bson:"dob,omitempty" json:"dob,omitempty"`
	Gender             string    `bson:"gender,omitempty" json:"gender,omitempty"`
	CreatedAt          time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time `bson:"updated_at" json:"updated_at"`
	Verified           bool      `bson:"verified" json:"verified,omitempty"`
	OtpForFP           string    `bson:"otpForFP,omitempty" json:"otpForFP,omitempty"`             //otp for Forget Password
	FpOtpExpiresAt     time.Time `bson:"fpOtpExpiresAt,omitempty" json:"fpOtpExpiresAt,omitempty"` // otp expiry for forget password
	OtpForVE           string    `bson:"otpForVE,omitempty" json:"otpForVE,omitempty"`             // otp for verifyEmail
	VeOtpExpiresAt     time.Time `bson:"veOtpExpiresAt,omitempty" json:"veOtpExpiresAt,omitempty"` // otp expiry for verify email
	OtpForLogin        string    `bson:"otpForLogin,omitempty" json:"otpForLogin,omitempty"`
	IsTwoFactorEnabled bool      `bson:"isTwoFactorEnabled, omitempty" json:"isTwoFactorEnabled,omitempty"`
	OtpExpiryForLogin  time.Time `bson:"otpExpiryForLogin,omitempty" json:"otpExpiryForLogin,omitempty"`
	Role               string    `bson:"role,omitempty" json:"role,omitempty"`
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
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type Organization struct {
	Name string `bson:"name" json:"name"`
}
