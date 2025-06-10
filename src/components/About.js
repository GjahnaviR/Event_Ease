// src/components/About.js
import React from 'react';
import { Link } from 'react-router-dom';
import './About.css';

const About = () => {
  return (
    <div className="about-container">
      <div className="about-header">
        <h1>Welcome to EventEase</h1>
        <p>Your premier event management partner since 2010. We specialize in creating memorable experiences, from corporate conferences to dream weddings, making event planning seamless and stress-free.</p>
      </div>

      <div className="about-grid">
        <div className="about-card">
          <h2>Our Mission</h2>
          <p>To transform the way events are planned and executed by providing innovative solutions that make event management accessible, efficient, and enjoyable for everyone. We believe in creating experiences that leave lasting impressions.</p>
        </div>

        <div className="about-card">
          <h2>Our Vision</h2>
          <p>To be the leading event management platform known for exceptional service, cutting-edge technology, and creating meaningful connections between event planners, vendors, and clients.</p>
        </div>

        <div className="about-card">
          <h2>Our Values</h2>
          <p>Excellence, innovation, and client satisfaction drive everything we do. We're committed to transparent communication, reliable service, and delivering events that exceed expectations.</p>
        </div>
      </div>

      <div className="about-image-section">
        <div className="image-card">
          <img src="/images/event-planning.jpg" alt="Event Planning" />
          <div className="image-overlay">
            <h3>Comprehensive Planning</h3>
            <p>From concept to execution, we handle every detail</p>
          </div>
        </div>
        <div className="image-card">
          <img src="/images/event-success.jpg" alt="Event Success" />
          <div className="image-overlay">
            <h3>Proven Success</h3>
            <p>Thousands of successful events and happy clients</p>
          </div>
        </div>
      </div>

      <div className="team-section">
        <h2>Meet Our Expert Team</h2>
        <div className="team-grid">
          <div className="team-card">
            <img src="/images/team-1.jpg" alt="Team Member" className="team-image" />
            <div className="team-info">
              <h3>Sarah Johnson</h3>
              <p>Senior Event Planner</p>
            </div>
          </div>
          <div className="team-card">
            <img src="/images/team-2.jpg" alt="Team Member" className="team-image" />
            <div className="team-info">
              <h3>Michael Chen</h3>
              <p>Vendor Relations Manager</p>
            </div>
          </div>
          <div className="team-card">
            <img src="/images/team-3.jpg" alt="Team Member" className="team-image" />
            <div className="team-info">
              <h3>Emma Rodriguez</h3>
              <p>Client Experience Director</p>
            </div>
          </div>
        </div>
      </div>

      <div className="contact-section">
        <h2>Ready to Plan Your Event?</h2>
        <p>Let's create something extraordinary together</p>
        <Link to="/contact" className="contact-button">Get Started</Link>
      </div>
    </div>
  );
};

export default About;