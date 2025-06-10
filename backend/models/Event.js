const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
    },
    description: {
      type: String,
      required: true,
    },
    location: {
      type: String,
      required: true,
    },
    date: {
      type: Date,
      required: true,
    },
    price: {
      type: Number,
      required: true,
      min: 0,
    },
    imageUrl: {
      type: String,
      default: "/images/events/placeholder.jpg",
    },
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "EventCategory",
      required: true,
    },
    availableTickets: {
      type: Number,
      required: true,
      min: 0,
    },
    features: [
      {
        type: String,
      },
    ],
    organizer: {
      type: String,
    },
    contactEmail: {
      type: String,
    },
    benefits: [
      {
        type: String,
      },
    ],
    targetAudience: {
      type: String,
    },
    expectations: {
      type: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Event", eventSchema); 