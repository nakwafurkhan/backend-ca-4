const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log(" MongoDB connected"))
  .catch(err => console.error(" DB error:", err));

// User schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// POST /register - Register a new user
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create new user
    await User.create({ username, password: hashedPassword });
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(400).json({ message: "Registration failed", error: err.message });
  }
});

// POST /login - Login user and set cookie
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

   
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

   
    const token = jwt.sign({ userId: user._id }, process.env.SECRETKEY, { expiresIn: "1h" });

    
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, 
      sameSite: "strict",
    });

    res.json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ message: "Login error", error: err.message });
  }
});


const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
