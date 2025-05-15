package main

import "time"

type User struct {
	Name     string    `bson:"name"`
	Email    string    `bson:"email"`
	Password string    `bson:"password"`
	Dob      time.Time `bson:"dob"`
}
