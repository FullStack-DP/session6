const mongoose = require("mongoose");
const express = require("express");
const app = express();
const tourRouter = require("../routes/tourRouter");
const userRouter = require("../routes/userRouter");
const {
  unknownEndpoint,
  errorHandler,
} = require("../middleware/customMiddleware");

// Middleware to parse JSON
app.use(express.json());
 
// Use the tourRouter for all "/tours" routes
app.use("/api/tours", tourRouter);

// Use the userRouter for all /users routes
app.use("/api/users", userRouter);

app.use(unknownEndpoint);
app.use(errorHandler);

mongoose
  .connect( "mongodb://localhost:27017/web-dev")
  .then(() => {
    console.log("connected to db");
  })
  .catch((error) => {
    console.error(error);
  });

module.exports = app;
