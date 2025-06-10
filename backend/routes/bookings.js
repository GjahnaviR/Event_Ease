const express = require("express");
const router = express.Router();
const Booking = require("../models/Booking");
const Event = require("../models/Event");
const { protect, restrictTo } = require("../middleware/auth");

// Get all bookings (admin only)
router.get("/", protect, restrictTo("admin"), async (req, res) => {
  try {
    const bookings = await Booking.find()
      .populate("user", "name email")
      .populate("event", "name location date price imageUrl");
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get user's bookings
router.get("/my-bookings", protect, async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.user.id }).populate(
      "event",
      "name location imageUrl price date description"
    );
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get single booking
router.get("/:id", protect, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id)
      .populate("user", "name email")
      .populate("event", "name location imageUrl price date description");

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    // Check if user is authorized to view this booking
    if (
      booking.user._id.toString() !== req.user.id &&
      req.user.role !== "admin"
    ) {
      return res.status(403).json({ message: "Not authorized" });
    }

    res.json(booking);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Create booking
router.post("/", protect, async (req, res) => {
  try {
    const {
      eventId,
      startDate,
      endDate,
      numberOfTickets,
      specialRequests,
    } = req.body;

    // Check if event exists and has available tickets
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    if (event.availableTickets < numberOfTickets) {
      return res.status(400).json({ message: "Not enough available tickets" });
    }

    // Calculate total price
    const totalPrice = event.price * numberOfTickets;

    // Create booking
    const booking = new Booking({
      user: req.user.id,
      event: eventId,
      startDate,
      endDate,
      numberOfTickets,
      totalPrice,
      specialRequests,
    });

    await booking.save();

    // Update available tickets
    event.availableTickets -= numberOfTickets;
    await event.save();

    res.status(201).json(booking);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Update booking status (admin only)
router.patch("/:id/status", protect, restrictTo("admin"), async (req, res) => {
  try {
    const { status } = req.body;
    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    booking.status = status;
    await booking.save();

    res.json(booking);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Cancel booking
router.delete("/:id", protect, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    // Check if user is authorized to cancel this booking
    if (booking.user.toString() !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ message: "Not authorized" });
    }

    // Update available tickets
    const event = await Event.findById(booking.event);
    if (event) {
      event.availableTickets += booking.numberOfTickets;
      await event.save();
    }

    await booking.deleteOne();
    res.json({ message: "Booking cancelled" });
  } catch (err) {
    console.error("Error during booking cancellation:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
