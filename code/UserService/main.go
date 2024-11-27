package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/rs/cors"
	"github.com/gorilla/mux"
	_ "github.com/go-sql-driver/mysql"
)

/*
set DB_USER=root
set DB_PASSWORD=j5WCx4b8X9Mk
set DB_HOST=127.0.0.1:3306
set DB_NAME=carsharingdb
go run "C:\Users\jnek6\OneDrive\Desktop\NP\3.2\CNAD\Assignment 1\CNAD-1_S10245614\code\UserService\main.go"

curl -X POST "http://localhost:5000/api/users/register" -H "Content-Type: application/json" -d "{\"email\": \"ulysses@gmail.com\",\"password\": \"qwerty\"}"
curl -X POST "http://localhost:5000/api/users/login" -H "Content-Type: application/json" -d "{\"email\": \"ulysses@gmail.com\", \"password\": \"qwerty\"}"
curl -X GET "http://localhost:5000/api/users/1" -H "Content-Type: application/json"
curl -X PUT "http://localhost:5000/api/users/1" -H "Content-Type: application/json" -d "{\"email\": \"odysseus@gmail.com\", \"password\": \"asdfg\", \"rateDiscount\": 15.5, \"bookingLimit\": 2, \"membershipTier\": \"Premium\", \"membershipStart\": \"2024-01-01 00:00:00\", \"membershipEnd\": \"2024-12-31 23:59:59\"}"
*/

// Normalization - Membership is stored within User as membership details are unlikely to be updated frequently
type User struct {
	UserID          int          `json:"id,omitempty"`
	Email           string       `json:"email,omitempty"`
	Password        string       `json:"password,omitempty"`
	RateDiscount    float64      `json:"rateDiscount,omitempty"`
	BookingLimit    int          `json:"bookingLimit,omitempty"`
	MembershipTier  string       `json:"membershipTier,omitempty"`
	MembershipStart sql.NullTime `json:"membershipStart,omitempty"`
	MembershipEnd   sql.NullTime `json:"membershipEnd,omitempty"`
}

// Custom Unmarshal for User struct to handle sql.NullTime
func (u *User) UnmarshalJSON(data []byte) error {
	type Alias User
	aux := &struct {
		MembershipStart string `json:"membershipStart,omitempty"`
		MembershipEnd   string `json:"membershipEnd,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(u),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Convert membershipStart and membershipEnd from string to sql.NullTime
	if aux.MembershipStart != "" {
		t, err := time.Parse("2006-01-02 15:04:05", aux.MembershipStart)
		if err != nil {
			return fmt.Errorf("invalid format for membershipStart: %v", err)
		}
		u.MembershipStart = sql.NullTime{Time: t, Valid: true}
	}

	if aux.MembershipEnd != "" {
		t, err := time.Parse("2006-01-02 15:04:05", aux.MembershipEnd)
		if err != nil {
			return fmt.Errorf("invalid format for membershipEnd: %v", err)
		}
		u.MembershipEnd = sql.NullTime{Time: t, Valid: true}
	}

	return nil
}

func main() {
	// Get database connection details from environment variables
	dbUser, dbPassword, dbHost, dbName := os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_NAME") // Get Environment Vars

	// Check if all necessary environment variables are set
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbName == "" {
		log.Fatal("Database credentials not fully set in environment variables")
	}

	// Initialize the router and start the server
	router := mux.NewRouter()

	// Handler Funtions
	router.HandleFunc("/api/users/register", func(w http.ResponseWriter, r *http.Request) { // Register a new user
		registerUserHandler(w, r, dbUser, dbPassword, dbHost, dbName)
	}).Methods("POST")
	router.HandleFunc("/api/users/login", func(w http.ResponseWriter, r *http.Request) { // User login with authentication
		userLoginHandler(w, r, dbUser, dbPassword, dbHost, dbName)
	}).Methods("POST")
	router.HandleFunc("/api/users/{id}", func(w http.ResponseWriter, r *http.Request) { // Retrieve user information
		getUserHandler(w, r, dbUser, dbPassword, dbHost, dbName)
	}).Methods("GET")
	router.HandleFunc("/api/users/{id}", func(w http.ResponseWriter, r *http.Request) { // Update user profile
		updateUserHandler(w, r, dbUser, dbPassword, dbHost, dbName)
	}).Methods("PUT")

	// CORS - Enables API calls from other ports
	c := cors.New(cors.Options{
        AllowedOrigins: []string{"http://localhost:8000"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
        AllowedHeaders: []string{"Content-Type", "Authorization"},
    })
    handler := c.Handler(router)

	log.Println("Starting server on :5000")
	if err := http.ListenAndServe(":5000", handler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// Register a new user
func registerUserHandler(w http.ResponseWriter, r *http.Request, dbUser, dbPassword, dbHost, dbName string) {
	// Build DSN for secure database connection
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("Database connection error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Decode the incoming JSON request body
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		log.Println("JSON decoding error:", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Prepare the SQL INSERT statement
	insertQuery := "INSERT INTO Users (Email, Password, BookingLimit, MembershipTier) VALUES (?, ?, 1, \"Basic\")"
	_, err = db.Exec(insertQuery, u.Email, hashedPassword)
	if err != nil {
		log.Println("Database insert error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set response headers and send a success message
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	response := map[string]string{
		"message": "Registration successful",
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("JSON encoding error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// User Login
func userLoginHandler(w http.ResponseWriter, r *http.Request, dbUser, dbPassword, dbHost, dbName string) {
	// Build DSN for secure database connection
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("Database connection error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Decode the incoming JSON request body
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		log.Println("JSON decoding error:", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Prepare the SQL SELECT statement to check for user credentials
	var storedUserID int
	var storedPassword string
	var storedEmail string

	selectQuery := "SELECT UserID, Email, Password FROM Users WHERE Email = ?"

	// Query the database for a user with the provided email
	err = db.QueryRow(selectQuery, u.Email).Scan(&storedUserID, &storedEmail, &storedPassword)
	if err == sql.ErrNoRows {
		// If no user is found
		http.Error(w, "Invalid email", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Println("Database query error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Compare entered password with stored password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(u.Password))
	if err != nil {
		http.Error(w, "Invalid passsword", http.StatusUnauthorized)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Respond with success message
	response := map[string]interface{}{
		"message": "Login successful",
		"user_id": storedUserID, // Return User ID
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("JSON encoding error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Get User Profile
func getUserHandler(w http.ResponseWriter, r *http.Request, dbUser, dbPassword, dbHost, dbName string) {
	// Function for parsing NullTime
	parseNullTime := func(byteValue []uint8) (sql.NullTime, error) {
		if byteValue == nil || len(byteValue) == 0 {
			return sql.NullTime{Valid: false}, nil // Return invalid NullTime for NULL values
		}

		// Convert []uint8 to string and parse to time.Time
		parsedTime, err := time.Parse("2006-01-02 15:04:05", string(byteValue))
		if err != nil {
			return sql.NullTime{}, err
		}

		return sql.NullTime{
			Time:  parsedTime,
			Valid: true,
		}, nil
	}
	// Build DSN for secure database connection
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("Database connection error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Extract UserID from URL
	userID, err := strconv.Atoi(r.URL.Path[len("/api/users/"):])
	if err != nil {
		log.Println("Error converting UserID to int:", err)
		http.Error(w, "Invalid UserID", http.StatusBadRequest)
		return
	}

	// Prepare the SQL SELECT statement
	selectQuery := "SELECT Email, RateDiscount, BookingLimit, MembershipTier, MembershipStart, MembershipEnd FROM Users WHERE UserID = ?"
	var email, membershipTier string
	var rateDiscount float64
	var bookingLimit int
	var membershipStart, membershipEnd []uint8

	// Query the database for the user
	err = db.QueryRow(selectQuery, userID).Scan(&email, &rateDiscount, &bookingLimit, &membershipTier, &membershipStart, &membershipEnd)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Println("Database query error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Convert membershipStart and membershipEnd to NullTIme
	parsedStart, err := parseNullTime(membershipStart)
	if err != nil {
		log.Println("Unable to convert MembershipStart to Time:", err)
		http.Error(w, "Invalid MembershipStart", http.StatusBadRequest)
		return
	}
	parsedEnd, err := parseNullTime(membershipEnd)
	if err != nil {
		log.Println("Unable to convert MembershipEnd to Time:", err)
		http.Error(w, "Invalid MembershipEnd", http.StatusBadRequest)
		return
	}

	// Prepare response map
	response := map[string]interface{}{
		"email":          email,
		"rateDiscount":   rateDiscount,
		"bookingLimit":   bookingLimit,
		"membershipTier": membershipTier,
		"membershipStart": func() interface{} {
			if parsedStart.Valid {
				return parsedStart.Time
			}
			return nil
		}(),
		"membershipEnd": func() interface{} {
			if parsedEnd.Valid {
				return parsedEnd.Time
			}
			return nil
		}(),
	}
	log.Println(membershipStart)

	// Encode the response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("JSON encoding error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Update User Profile
func updateUserHandler(w http.ResponseWriter, r *http.Request, dbUser, dbPassword, dbHost, dbName string) {
	// Build DSN for secure database connection
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("Database connection error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Decode the incoming JSON request body
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		log.Println("JSON decoding error:", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	userID, err := strconv.Atoi(r.URL.Path[len("/api/users/"):])
	if err != nil {
		log.Println("Error converting UserID to int:", err)
		http.Error(w, "Invalid UserID", http.StatusBadRequest)
		return
	}

	// Prepare the SQL UPDATE statement
	insertQuery := "UPDATE Users SET Email = ?, Password = ?, RateDiscount = ?, BookingLimit = ?, MembershipTier = ?, MembershipStart = ?, MembershipEnd = ? WHERE UserID = ?"
	result, err := db.Exec(insertQuery, u.Email, u.Password, u.RateDiscount, u.BookingLimit, u.MembershipTier, u.MembershipStart, u.MembershipEnd, userID)
	if err != nil {
		log.Println("Database update error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check if any row was affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println("Error checking rows affected:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "User not found or no changes made", http.StatusNotFound)
		return
	}

	// Set response headers and send a success message
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	response := map[string]string{
		"message": "Updated user details",
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("JSON encoding error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
