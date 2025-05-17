package main

import "time"

type UserDto struct {
	Name      string    `bson:"name" json:"name"`
	Email     string    `bson:"email" json:"email"`
	Password  string    `bson:"password" json:"password"`
	Dob       time.Time `bson:"dob,omitempty" json:"dob,omitempty"`
	Gender    string    `bson:"gender,omitempty" json:"gender,omitempty"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type Response struct {
	Message string `json:"message"`
}

type LoginDto struct {
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"`
}
