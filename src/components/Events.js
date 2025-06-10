import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { eventService } from '../services/api';
import './Events.css';

const Events = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const data = await eventService.getAll();
        setEvents(data);
      } catch (err) {
        setError("Failed to load events. Please try again later.");
        console.error("Error fetching events:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, []);

  if (loading) {
    return (
      <div className="events-loading">
        <div className="loading-spinner"></div>
        <p>Loading events...</p>
      </div>
    );
  }

  if (error) {
    return <div className="error-message">{error}</div>;
  }

  return (
    <div className="events-page">
      <div className="events-header">
        <h1>Discover Amazing Events</h1>
        <p>Find and book your next unforgettable experience</p>
      </div>

      <div className="events-grid">
        {events.length === 0 ? (
          <div className="no-events">
            <p>No events found.</p>
            <p>Check back soon for new events!</p>
          </div>
        ) : (
          events.map((event) => (
            <div className="event-card" key={event._id}>
              <div className="event-image">
                <img src={event.imageUrl} alt={event.name} />
                <div className="event-price">₹{event.price}</div>
              </div>
              <div className="event-content">
                <h3>{event.name}</h3>
                <p className="event-description">{event.description}</p>
                <div className="event-details">
                  <div className="event-detail">
                    <i className="fas fa-map-marker-alt"></i>
                    <span>{event.location}</span>
                  </div>
                  <div className="event-detail">
                    <i className="fas fa-calendar-alt"></i>
                    <span>{new Date(event.date).toLocaleDateString()}</span>
                  </div>
                  <div className="event-detail">
                    <i className="fas fa-ticket-alt"></i>
                    <span>{event.availableTickets} tickets left</span>
                  </div>
                </div>
                <Link to={`/events/${event._id}`} className="view-event-button">
                  View Details
                </Link>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Events; 