// src/App.js
import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { Elements } from '@stripe/react-stripe-js';
import { loadStripe } from '@stripe/stripe-js';
import Navbar from "./components/Navbar";
import Home from "./components/Home";
import About from "./components/About";
import Contact from "./components/Contact";
import Login from "./components/Login";
import Signup from "./components/Signup";
import Events from "./components/Events";
import EventDetail from "./components/EventDetail";
import Booking from "./components/Booking";
import BookingPage from "./components/BookingPage";
import Dashboard from "./components/Dashboard";
import AddEvent from "./components/AddEvent";
import AdminDashboard from "./components/AdminDashboard";
import ProtectedRoute from "./components/ProtectedRoute";
import EditProfile from "./components/EditProfile";
import "./App.css";

// Initialize Stripe
const stripePromise = loadStripe('your_publishable_key'); // Replace with your Stripe publishable key

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userRole = localStorage.getItem('userRole');
    if (token) {
      setIsAuthenticated(true);
      setIsAdmin(userRole === 'admin');
    }
  }, []);

  const handleAuthChange = () => {
    const token = localStorage.getItem('authToken');
    const userRole = localStorage.getItem('userRole');
    const newIsAuthenticated = !!token;
    const newIsAdmin = token && userRole === 'admin';
    setIsAuthenticated(newIsAuthenticated);
    setIsAdmin(newIsAdmin);
    console.log('handleAuthChange triggered:');
    console.log('  isAuthenticated:', newIsAuthenticated);
    console.log('  isAdmin:', newIsAdmin);
  };

  return (
    <Router>
      <div className="App">
        <Navbar isAuthenticated={isAuthenticated} isAdmin={isAdmin} handleAuthChange={handleAuthChange} />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/about" element={<About />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/login" element={<Login handleAuthChange={handleAuthChange} />} />
          <Route path="/signup" element={<Signup handleAuthChange={handleAuthChange} />} />
          <Route path="/events" element={<Events />} />
          <Route path="/events/:id" element={<EventDetail />} />
          <Route path="/booking/:id" element={<Booking />} />
          <Route 
            path="/book-tickets" 
            element={
              <Elements stripe={stripePromise}>
                <BookingPage />
              </Elements>
            } 
          />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/add-event" element={<AddEvent />} />
          <Route
            path="/admin/dashboard"
            element={
              <ProtectedRoute isAuthenticated={isAuthenticated} isAdmin={isAdmin}>
                <AdminDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/edit-profile"
            element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <EditProfile isAuthenticated={isAuthenticated} handleAuthChange={handleAuthChange} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/my-bookings"
            element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <Dashboard />
              </ProtectedRoute>
            }
          />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
