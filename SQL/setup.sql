DROP database IF EXISTS carsharingdb;
CREATE database carsharingdb;
use carsharingdb;

CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Email VARCHAR(255) NOT NULL UNIQUE,
    Password VARCHAR(60) NOT NULL,
    RateDiscount DECIMAL(5, 2) DEFAULT 0.00,  -- Discount as percentage
    BookingLimit INT NOT NULL,
    MembershipTier VARCHAR(50) NOT NULL,       -- e.g., 'Basic', 'Premium', 'VIP'
    MembershipStart DATETIME,
    MembershipEnd DATETIME
);

CREATE TABLE Vehicles (
    VehicleID INT PRIMARY KEY AUTO_INCREMENT,
    PlateNumber VARCHAR(20) NOT NULL UNIQUE,
    Rate DECIMAL(10, 2) NOT NULL,             -- Rate per hour or similar
    Location VARCHAR(255) NOT NULL,
    Latitude DECIMAL(9, 6),                   -- Coordinate-based location (optional)
    Longitude DECIMAL(9, 6),
    ChargeLevel DECIMAL(5, 2) NOT NULL,       -- Percentage from 0 to 100
    Cleanliness VARCHAR(20) NOT NULL,         -- e.g., 'Clean', 'Moderate', 'Dirty'
    VehicleStatus VARCHAR(50) NOT NULL,       -- e.g., 'Available', 'Booked', 'In Use', 'Maintenance'
    VehicleType VARCHAR(50) NOT NULL          -- e.g., 'Sedan', 'SUV', 'Electric Bike'
);

CREATE TABLE Rentals (
    RentalID INT PRIMARY KEY AUTO_INCREMENT,
    Cost DECIMAL(10, 2) NOT NULL,
    EstimatedCost DECIMAL(10, 2),             -- Optional, for real-time cost estimation
    RentalStart DATETIME NOT NULL,             -- Start date and time of rental
    RentalEnd DATETIME NOT NULL,               -- End date and time of rental
    ReturnDate DATETIME,                      -- Actual return date and time
    PaymentStatus VARCHAR(50) NOT NULL,       -- e.g., 'Pending', 'Paid', 'Cancelled',
    RentalStatus VARCHAR(50) NOT NULL,
    UserID INT NOT NULL,
    VehicleID INT NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (VehicleID) REFERENCES Vehicles(VehicleID)
);