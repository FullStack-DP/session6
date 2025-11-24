const mongoose = require("mongoose");
const supertest = require("supertest");
const app = require("./app-test"); // Your Express app
const api = supertest(app);
const User = require("../models/userModel");

const users = [
  {
    name: "John Doe",
    email: "john@example.com",
    password: "password123",
    phone_number: "1234567890",
    gender: "Male",
    date_of_birth: "1990-01-01",
    membership_status: "Inactive",
  },
  {
    name: "Jane Smith",
    email: "jane@example.com",
    password: "password456",
    phone_number: "0987654321",
    gender: "Female",
    date_of_birth: "1992-05-15",
    membership_status: "Inactive",
  },
];
 
describe("User Controller", () => {
  beforeEach(async () => {
    await User.deleteMany({});
    await User.insertMany(users);
  });

  afterAll(() => {
    mongoose.connection.close();
  });

  // Test GET /api/users
  it("should return all users as JSON when GET /api/users is called", async () => {
    const response = await api
      .get("/api/users")
      .expect(200)
      .expect("Content-Type", /application\/json/);

    expect(response.body).toHaveLength(users.length);
  });

  // Test POST /api/users
  it("should create a new user when POST /api/users is called", async () => {
    const newUser = {
      name: "Alice Johnson",
      email: "alice@example.com",
      password: "password789",
      phone_number: "1112223333",
      gender: "Female",
      date_of_birth: "1993-03-22",
      membership_status: "Active",
    };

    await api
      .post("/api/users")
      .send(newUser)
      .expect(201)
      .expect("Content-Type", /application\/json/);

    const usersAfterPost = await User.find({});
    expect(usersAfterPost).toHaveLength(users.length + 1);
    const emails = usersAfterPost.map((user) => user.email);
    expect(emails).toContain(newUser.email);
  });

  it("should not create a user with duplicate email", async () => {
    const duplicateUser = {
      name: "Duplicate User",
      email: "john@example.com", // Duplicate email
      password: "password123",
      phone_number: "5555555555",
      gender: "Male",
      date_of_birth: "1995-07-19",
      membership_status: "Active",
    };

    const response = await api
      .post("/api/users")
      .send(duplicateUser)
      .expect(400);

    expect(response.body.message).toBe("Failed to create user");

    const usersAfterPost = await User.find({});
    expect(usersAfterPost).toHaveLength(users.length);
  });

  // Test GET /api/users/:id
  it("should return one user by ID when GET /api/users/:id is called", async () => {
    const user = await User.findOne();
    await api
      .get(`/api/users/${user._id}`)
      .expect(200)
      .expect("Content-Type", /application\/json/);
  });

  it("should return 404 for a non-existing user ID", async () => {
    const nonExistentId = new mongoose.Types.ObjectId();
    await api.get(`/api/users/${nonExistentId}`).expect(404);
  });

  // Test PUT /api/users/:id
  it("should update one user by ID with partial data when PUT /api/users/:id is called", async () => {
    const user = await User.findOne(); // Retrieve an existing user

    const updatedFields = {
      phone_number: "9876543210", // Only updating one field
      membership_status: "Active",
    };

    const response = await api
      .put(`/api/users/${user._id}`)
      .send(updatedFields)
      .expect(200)
      .expect("Content-Type", /application\/json/);

    const updatedUserCheck = await User.findById(user._id);
    expect(updatedUserCheck.phone_number).toBe(updatedFields.phone_number);
    expect(updatedUserCheck.membership_status).toBe(
      updatedFields.membership_status
    );
  });

  it("should return 400 for invalid user ID when PUT /api/users/:id", async () => {
    const invalidId = "12345";
    await api.put(`/api/users/${invalidId}`).send({}).expect(400);
  });

  // Test DELETE /api/users/:id
  it("should delete one user by ID when DELETE /api/users/:id is called", async () => {
    const user = await User.findOne();
    await api.delete(`/api/users/${user._id}`).expect(204);

    const deletedUserCheck = await User.findById(user._id);
    expect(deletedUserCheck).toBeNull();
  });

  it("should return 400 for invalid user ID when DELETE /api/users/:id", async () => {
    const invalidId = "12345";
    await api.delete(`/api/users/${invalidId}`).expect(400);
  });
});
