const express = require("express");
const router = express.Router();
const Event = require("../models/Event");
const { protect, restrictTo } = require("../middleware/auth");

// Get all events
router.get("/", async (req, res) => {
  try {
    const events = await Event.find().populate("category", "name");
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get single event by ID
router.get("/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate(
      "category",
      "name"
    );
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Search events
router.get("/search", async (req, res) => {
  try {
    const { name, location, category } = req.query;
    const query = {};

    if (name) {
      query.name = { $regex: name, $options: "i" };
    }
    if (location) {
      query.location = { $regex: location, $options: "i" };
    }
    if (category) {
      // This assumes category is the ID. If it's a name, you'd need to find the ID first.
      query.category = category;
    }

    const events = await Event.find(query).populate("category", "name");
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Create a new event (Admin only)
router.post("/", protect, restrictTo("admin"), async (req, res) => {
  try {
    const {
      name,
      description,
      location,
      date,
      price,
      imageUrl,
      category,
      availableTickets,
      features,
      organizer,
      contactEmail,
      benefits,
      targetAudience,
      expectations,
    } = req.body;

    const newEvent = new Event({
      name,
      description,
      location,
      date,
      price,
      imageUrl,
      category,
      availableTickets,
      features,
      organizer,
      contactEmail,
      benefits,
      targetAudience,
      expectations,
    });

    await newEvent.save();
    res.status(201).json(newEvent);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Update an event (Admin only)
router.put("/:id", protect, restrictTo("admin"), async (req, res) => {
  try {
    const {
      name,
      description,
      location,
      date,
      price,
      imageUrl,
      category,
      availableTickets,
      features,
      organizer,
      contactEmail,
      benefits,
      targetAudience,
      expectations,
    } = req.body;

    const updatedEvent = await Event.findByIdAndUpdate(
      req.params.id,
      {
        name,
        description,
        location,
        date,
        price,
        imageUrl,
        category,
        availableTickets,
        features,
        organizer,
        contactEmail,
        benefits,
        targetAudience,
        expectations,
      },
      { new: true }
    );

    if (!updatedEvent) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json(updatedEvent);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete an event (Admin only)
router.delete("/:id", protect, restrictTo("admin"), async (req, res) => {
  try {
    const deletedEvent = await Event.findByIdAndDelete(req.params.id);
    if (!deletedEvent) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json({ message: "Event deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router; 