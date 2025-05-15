package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func addUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if r.Body == nil {
		json.NewEncoder(w).Encode("please provide data")
		return
	}
	json.NewDecoder(r.Body).Decode(&user)

	result, _ := collection.InsertOne(ctx, user)
	fmt.Println(result.InsertedID)
	json.NewEncoder(w).Encode(user)

}

func getUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var users []User
	var user User
	cursor,_:=collection.Find(ctx, bson.M{})
	defer cursor.Close(ctx);
	for cursor.Next(ctx){
		cursor.Decode(&user);
		users=append(users,user);
	}

	json.NewEncoder(w).Encode(users)
}
