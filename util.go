package main

import "time"

type UserDto struct {
	Name     string    `bson:"name" json:"name"`
	Email    string    `bson:"email" json:"email"`
	Password string    `bson:"password" json:"password"`
	Dob      time.Time `bson:"dob" json:"dob"`
}

type Response struct {
	Message string `json:"message"`
}

type LoginDto struct {
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
}
