import React, { useState, useEffect } from "react";
import { eventBookingService } from "../services/api";
import "./AdminDashboard.css";

const AdminDashboard = () => {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("pending");
  const [showRefundModal, setShowRefundModal] = useState(false);
  const [selectedBooking, setSelectedBooking] = useState(null);

  useEffect(() => {
    fetchBookings();
  }, []);

  const fetchBookings = async () => {
    try {
      setLoading(true);
      const data = await eventBookingService.getAll();
      setBookings(data);
      setError(null);
    } catch (err) {
      setError("Failed to load bookings. Please try again later.");
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdate = async (bookingId, newStatus) => {
    try {
      if (newStatus === "cancelled") {
        const booking = bookings.find(b => b._id === bookingId);
        if (booking.paymentStatus === "completed") {
          setSelectedBooking(booking);
          setShowRefundModal(true);
          return;
        }
      }
      await eventBookingService.updateStatus(bookingId, newStatus);
      fetchBookings();
    } catch (err) {
      setError("Failed to update booking status. Please try again.");
    }
  };

  const handleRefund = async () => {
    try {
      await eventBookingService.processRefund(selectedBooking._id);
      await eventBookingService.updateStatus(selectedBooking._id, "cancelled");
      setShowRefundModal(false);
      setSelectedBooking(null);
      fetchBookings();
    } catch (err) {
      setError("Failed to process refund. Please try again.");
    }
  };

  const filteredBookings = bookings.filter((booking) => {
    if (activeTab === "pending") return booking.status === "pending";
    if (activeTab === "confirmed") return booking.status === "confirmed";
    if (activeTab === "cancelled") return booking.status === "cancelled";
    return true;
  });

  if (loading) {
    return <div className="loading">Loading bookings...</div>;
  }

  if (error) {
    return <div className="error-message">{error}</div>;
  }

  return (
    <div className="admin-dashboard">
      <h1>Admin Dashboard</h1>
      
      <div className="tabs">
        <button
          className={`tab ${activeTab === "pending" ? "active" : ""}`}
          onClick={() => setActiveTab("pending")}
        >
          Pending Bookings
        </button>
        <button
          className={`tab ${activeTab === "confirmed" ? "active" : ""}`}
          onClick={() => setActiveTab("confirmed")}
        >
          Confirmed Bookings
        </button>
        <button
          className={`tab ${activeTab === "cancelled" ? "active" : ""}`}
          onClick={() => setActiveTab("cancelled")}
        >
          Cancelled Bookings
        </button>
      </div>

      <div className="bookings-list">
        {filteredBookings.length === 0 ? (
          <div className="empty-bookings">No {activeTab} bookings found</div>
        ) : (
          filteredBookings.map((booking) => (
            <div key={booking._id} className="booking-item">
              <div className="booking-image">
                <img src={booking.event.image} alt={booking.event.name} />
              </div>
              <div className="booking-details">
                <h3>{booking.event.name}</h3>
                <p>User: {booking.user.name}</p>
                <p>Date: {new Date(booking.startDate).toLocaleDateString()}</p>
                <p>Tickets: {booking.numberOfTickets}</p>
                <p>Total Price: ₹{booking.totalPrice}</p>
                <p>Status: <span className={`status ${booking.status}`}>{booking.status}</span></p>
                <p>Payment: <span className={`status ${booking.paymentStatus}`}>{booking.paymentStatus}</span></p>
                
                <div className="admin-actions">
                  {booking.status === "pending" && (
                    <>
                      <button
                        className="confirm-button"
                        onClick={() => handleStatusUpdate(booking._id, "confirmed")}
                      >
                        Confirm Booking
                      </button>
                      <button
                        className="cancel-button"
                        onClick={() => handleStatusUpdate(booking._id, "cancelled")}
                      >
                        Cancel Booking
                      </button>
                    </>
                  )}
                  {booking.status === "confirmed" && (
                    <button
                      className="cancel-button"
                      onClick={() => handleStatusUpdate(booking._id, "cancelled")}
                    >
                      Cancel Booking
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {showRefundModal && selectedBooking && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Process Refund</h2>
            <p>This booking has been paid for. Would you like to process a refund?</p>
            <div className="modal-actions">
              <button className="confirm-button" onClick={handleRefund}>
                Yes, Process Refund
              </button>
              <button className="cancel-button" onClick={() => setShowRefundModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard; 