import React from "react";
import { useLocation, Link } from "react-router-dom";
import "./BookingConfirmation.css";

const BookingConfirmation = () => {
  const location = useLocation();
  const bookingDetails = location.state?.bookingDetails || {};
  const paymentDetails = location.state?.paymentDetails || {};
  const itemType = location.state?.type || "";
  const itemName = location.state?.itemName || "";
  const price = location.state?.price || 0;

  // Generate a random booking reference number
  const bookingReference = `BK${Math.random()
    .toString(36)
    .substr(2, 9)
    .toUpperCase()}`;

  // Ensure price is not negative
  const safePrice = Math.max(0, price);

  return (
    <div className="confirmation-container">
      <div className="confirmation-content">
        <div className="success-icon">✓</div>
        <h1>Booking Confirmed!</h1>
        <p className="confirmation-message">
          Thank you for your booking. Your payment has been processed
          successfully.
        </p>

        <div className="booking-details">
          <h2>Booking Details</h2>
          <div className="detail-item">
            <span>Booking Reference:</span>
            <span className="reference">{bookingReference}</span>
          </div>
          <div className="detail-item">
            <span>Item Type:</span>
            <span className="capitalize">{itemType}</span>
          </div>
          <div className="detail-item">
            <span>Item Name:</span>
            <span>{itemName}</span>
          </div>

          {itemType === "destination" && (
            <>
              <div className="detail-item">
                <span>Start Date:</span>
                <span>{bookingDetails.startDate}</span>
              </div>
              <div className="detail-item">
                <span>End Date:</span>
                <span>{bookingDetails.endDate}</span>
              </div>
              <div className="detail-item">
                <span>Travelers:</span>
                <span>{bookingDetails.travelers}</span>
              </div>
              <div className="detail-item">
                <span>Package:</span>
                <span className="capitalize">{bookingDetails.package}</span>
              </div>
            </>
          )}

          {itemType === "flight" && (
            <>
              <div className="detail-item">
                <span>Flight Number:</span>
                <span>{bookingDetails.flightNumber}</span>
              </div>
              <div className="detail-item">
                <span>Date:</span>
                <span>{bookingDetails.date}</span>
              </div>
              <div className="detail-item">
                <span>Passengers:</span>
                <span>{bookingDetails.passengers}</span>
              </div>
              <div className="detail-item">
                <span>Class:</span>
                <span className="capitalize">{bookingDetails.class}</span>
              </div>
            </>
          )}

          {itemType === "hotel" && (
            <>
              <div className="detail-item">
                <span>Check-in:</span>
                <span>{bookingDetails.checkIn}</span>
              </div>
              <div className="detail-item">
                <span>Check-out:</span>
                <span>{bookingDetails.checkOut}</span>
              </div>
              <div className="detail-item">
                <span>Guests:</span>
                <span>{bookingDetails.guests}</span>
              </div>
              <div className="detail-item">
                <span>Room Type:</span>
                <span className="capitalize">{bookingDetails.roomType}</span>
              </div>
            </>
          )}

          <div className="detail-item total">
            <span>Total Amount:</span>
            <span>₹{safePrice.toLocaleString("en-IN")}</span>
          </div>
        </div>

        <div className="payment-details">
          <h2>Payment Details</h2>
          <div className="detail-item">
            <span>Card Number:</span>
            <span>{paymentDetails.cardNumber}</span>
          </div>
          <div className="detail-item">
            <span>Card Holder:</span>
            <span>{paymentDetails.cardHolder}</span>
          </div>
        </div>

        <div className="confirmation-actions">
          <Link to="/dashboard" className="dashboard-button">
            Go to Dashboard
          </Link>
          <Link to="/" className="home-button">
            Return to Home
          </Link>
        </div>

        <div className="confirmation-note">
          <p>
            A confirmation email has been sent to your registered email address
            with all the booking details.
          </p>
        </div>
      </div>
    </div>
  );
};

export default BookingConfirmation;
