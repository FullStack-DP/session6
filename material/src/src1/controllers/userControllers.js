const User = require("../models/userModel");

// GET /users
const getAllUsers = (req, res) => {
  const users = User.getAll();
  res.json(users);
};

// POST /users
const createUser = (req, res) => {
  const newUser = User.addOne({ ...req.body }); // Spread the req.body object

  if (newUser) {
    res.status(201).json(newUser);
  } else {
    // Handle error (e.g., failed to create user)
    res.status(400).json({ message: "Invalid user data" });
  }
};
 
// GET /users/:userId
const getUserById = (req, res) => {
  const userId = req.params.userId;
  const user = User.findById(userId);
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ message: "User not found" });
  }
};

// PUT /users/:userId
const updateUser = (req, res) => {
  const userId = req.params.userId;
  const updatedUser = User.updateOneById(userId, { ...req.body }); // Spread the req.body object

  if (updatedUser) {
    res.json(updatedUser);
  } else {
    // Handle update failure (e.g., user not found)
    res.status(404).json({ message: "User not found" });
  }
};

// DELETE /users/:userId
const deleteUser = (req, res) => {
  const userId = req.params.userId;
  const isDeleted = User.deleteOneById(userId);

  if (isDeleted) {
    res.status(204).send();
  } else {
    // Handle deletion failure (e.g., user not found)
    res.status(404).json({ message: "User not found" });
  }
};

module.exports = {
  getAllUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
};
