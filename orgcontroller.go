package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func insertOrg(w http.ResponseWriter, r *http.Request) {
	logger.Info("org insertion")
	w.Header().Set("Content-Type", "application/json")
	var org Organization
	json.NewDecoder(r.Body).Decode(&org)
	if r.Body == nil {
		//status code
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "please provide data"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//  protected using user token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {

		logger.Info("Missing token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "Missing token"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {

		logger.Info("Invalid token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "Invalid token format"})

		return
	}

	tokenStr := parts[1]
	// verify token
	userid, errr := VerifyToken(tokenStr)
	if errr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "unauthorized token"})
		return
	}
	logger.Info("User ID from token", "userid", userid)

	// add org to database
	result, err := db.Collection("organization").InsertOne(ctx, org)
	if err != nil {
		logger.Error("Error inserting organization", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Message: "Error inserting organization"})
		return
	}
	logger.Info("Organization inserted successfully", "orgID", result.InsertedID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "inserted"})

}
func updateOrg(w http.ResponseWriter, r *http.Request) {
	logger.Info("org update")
	w.Header().Set("Content-Type", "application/json")
	var org Organization
	json.NewDecoder(r.Body).Decode(&org)
	if r.Body == nil {
		//status code
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "please provide data"})
		return
	}
	// get object id from url
	params := mux.Vars(r)
	paramsId := params["id"]
	// convert orgID to object id
	objId, err := primitive.ObjectIDFromHex(paramsId)
	if err != nil {
		logger.Error("Invalid Object ID", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Invalid Object ID"})
	}

	//  protected using user token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {

		logger.Info("Missing token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "Missing token"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {

		logger.Info("Invalid token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "Invalid token format"})

		return
	}

	tokenStr := parts[1]
	// verify token
	userid, errr := VerifyToken(tokenStr)
	if errr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "unauthorized token"})
		return
	}
	logger.Info("User ID from token", "userid", userid)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// update org to database
	// create a filter to find the organization by ID
	filter := bson.M{"_id": objId}
	update := bson.M{"$set": bson.M{"name": org.Name}}
	result, _ := db.Collection("organization").UpdateOne(ctx, filter, update)
	if result.MatchedCount == 0 {
		logger.Error("Organization not found", "orgID", objId)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: "Organization not found"})
		return
	}
	logger.Info("Organization updated successfully")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "updated"})

}
func readSpecificOrg(w http.ResponseWriter, r *http.Request) {
	logger.Info("org read")
	w.Header().Set("Content-Type", "application/json")
	// get object id from url
	params := mux.Vars(r)
	paramsId := params["id"]
	// convert orgID to object id
	objId, err := primitive.ObjectIDFromHex(paramsId)
	if err != nil {
		logger.Error("Invalid Object ID", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Message: "Invalid Object ID"})
		return
	}

	//  protected using user token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {

		logger.Info("Missing token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "Missing token"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {

		logger.Info("Invalid token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "Invalid token format"})

		return
	}

	tokenStr := parts[1]
	// verify token
	userid, errr := VerifyToken(tokenStr)
	if errr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Message: "unauthorized token"})
		return
	}
	logger.Info("User ID from token", "userid", userid)
	// find org in database

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var org Organization
	err = db.Collection("organization").FindOne(ctx, bson.M{"_id": objId}).Decode(&org)
	if err != nil {
		logger.Error("Error finding organization", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Message: "Error finding organization"})
		return
	}
	logger.Info("Organization found successfully", "orgID", objId)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(org)

}
