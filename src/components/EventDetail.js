import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { eventService } from '../services/api';
import './EventDetail.css';

const EventDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [event, setEvent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchEvent = async () => {
      try {
        const data = await eventService.getById(id);
        setEvent(data);
      } catch (err) {
        setError("Failed to load event details. Please try again later.");
        console.error("Error fetching event details:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchEvent();
  }, [id]);

  const handleBookNow = () => {
    const isAuthenticated = localStorage.getItem('authToken');
    console.log('Auth token:', isAuthenticated);
    
    if (!isAuthenticated) {
      console.log('Not authenticated, redirecting to login');
      navigate('/login', { state: { from: `/events/${id}` } });
      return;
    }
    
    console.log('Authenticated, proceeding to booking');
    navigate(`/book-tickets`, { 
      state: { 
        eventId: id,
        eventName: event.name,
        eventDate: event.date,
        eventPrice: event.price
      }
    });
  };

  if (loading) {
    return <div className="loading">Loading event details...</div>;
  }

  if (error) {
    return <div className="error-message">{error}</div>;
  }

  if (!event) {
    return <div className="no-event-found">Event not found.</div>;
  }

  return (
    <div className="event-detail-container">
      <div className="event-header">
        <div className="event-title-section">
          <h1>{event.name}</h1>
          <span className="category">{event.category.name}</span>
        </div>
        <div className="event-contact">
          <p>Location: {event.location}</p>
          <p>Date: {new Date(event.date).toLocaleDateString()}</p>
          <p>Price: ₹{event.price}</p>
        </div>
      </div>

      <div className="event-image-container">
        {event.imageUrl && <img src={event.imageUrl} alt={event.name} className="event-image" />}
      </div>

      <div className="event-description">
        <h2>About this Event</h2>
        <p>{event.description}</p>
      </div>

      {event.features && event.features.length > 0 && (
        <div className="event-features">
          <h2>What to Expect</h2>
          <ul>
            {event.features.map((feature, index) => (
              <li key={index}>{feature}</li>
            ))}
          </ul>
        </div>
      )}

      {event.organizer && (
        <div className="event-organizer">
          <h2>Organizer</h2>
          <p>{event.organizer}</p>
          {event.contactEmail && <p>Contact: {event.contactEmail}</p>}
        </div>
      )}

      {event.benefits && event.benefits.length > 0 && (
        <div className="event-benefits">
          <h2>Benefits of Attending</h2>
          <ul>
            {event.benefits.map((benefit, index) => (
              <li key={index}>{benefit}</li>
            ))}
          </ul>
        </div>
      )}

      {event.targetAudience && (
        <div className="event-audience">
          <h2>Target Audience</h2>
          <p>{event.targetAudience}</p>
        </div>
      )}

      {event.expectations && (
        <div className="event-expectations">
          <h2>Expectations for Participants</h2>
          <p>{event.expectations}</p>
        </div>
      )}

      <div className="event-actions">
        <button 
          className="book-now-button"
          onClick={handleBookNow}
        >
          Book Now
        </button>
      </div>
    </div>
  );
};

export default EventDetail; 