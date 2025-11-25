# Hashing & Rainbow Attack

This activity consists of 2 parts

---
## Part 1: Password Hashing with Node.js, Express, and Crypto



### Learning Objectives

By the end of this lab, students will:
- Understand what **hashing** is and why it’s important for security.
- Learn that hashing is a **one-way function** (cannot be reversed).
- Use Node.js’s built-in **crypto library** to hash passwords.
- Build a simple Express server with MongoDB to store hashed passwords.


#### Step 1: Setup Project

1. Create a new folder for your project:
   ```bash
   mkdir hashing-lab
   cd hashing-lab
   ```
2. Initialize Node.js:
   ```bash
   npm init -y
   ```
3. Install dependencies:
   ```bash
   npm install express mongoose
   ```

#### Step 2: Import Libraries

We need three main libraries:
- **express** → to create the web server and endpoints.
- **mongoose** → to connect and interact with MongoDB.
- **crypto** → to hash passwords.

```js
const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");

const app = express();
app.use(express.json());
```

#### Step 3: Define User Schema

We’ll store:
- `username` → plain text
- `password` → plain text (for demonstration only, not secure!)
- `hashedPassword` → the hashed version of the password

```js
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  hashedPassword: String,
});

const User = mongoose.model("User", userSchema);
```

⚠️ **Note:** In real applications, we should **never store plain text passwords**. This is only for learning purposes.

#### Step 4: Connect to MongoDB

```js
mongoose
  .connect("mongodb://localhost:27017/be-lab")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));
```

#### Step 5: Hashing Function

We use **SHA-256** hashing algorithm from the crypto library.

```js
function hashPasswordWithSHA256(password) {
  const sha256Hash = crypto.createHash("sha256");
  sha256Hash.update(password);
  return sha256Hash.digest("hex");
}
```

##### Explanation:

- `crypto.createHash("sha256")` → creates a SHA-256 hashing object.
- `.update(password)` → feeds the password into the hashing function.
- `.digest("hex")` → outputs the hash as a hexadecimal string.

👉 Hashing is **one-way**:  
If you hash `"mypassword"`, you get something like:
```
34819d7beeabb9260a5c854bc85b3e44...
```
You **cannot reverse** this string back into `"mypassword"`.

#### Step 6: User Registration Endpoint

When a user registers, we hash their password before saving.

```js
app.post("/api/users", async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = hashPasswordWithSHA256(password);

  await User.create({ username, password, hashedPassword });
  res.status(201).json({ message: "User registered successfully" });
});
```

#### Step 7: Fetch Users

```js
app.get("/api/users", async (req, res) => {
  const allUsers = await User.find({});
  res.status(200).json(allUsers);
});
```

#### Step 8: Delete Users

```js
app.delete("/api/users/", async (req, res) => {
  await User.deleteMany();
  res.status(200).json({ message: "All Users deleted successfully" });
});
```

#### Step 9: Run the Server

```js
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```


### Key Concepts Recap

- **Hashing is one-way**: You can hash `"mypassword"` → `"34819d7..."`, but you cannot go backwards.
- **Why hashing?**  
  - Protects user passwords in case of a database leak.  
  - Even if attackers steal the database, they only see hashes.  
- **Crypto library**: Provides secure hashing algorithms like SHA-256.  
- **No reversal**: Hashing is not encryption. Encryption can be reversed with a key, hashing cannot.  

###  Exercise
1. Register a user with:
   ```json
   {
     "username": "alice",
     "password": "mypassword"
   }
   ```
2. Fetch all users (`GET /api/users`) and observe:
   - Plain password stored (for demo).
   - Hashed password stored (long hex string).
3. Try changing the password slightly (e.g., `"mypassword1"`) and notice how the hash changes completely.
4. Reflect: Why is hashing safer than storing plain text?


---
## Part 2: Simulating a Rainbow Table Attack


### Learning Objectives
By the end of this lab, students will:
- Understand what a **rainbow table attack** is.
- See how attackers can use precomputed hashes of common passwords to recover user credentials.
- Learn why **unsalted hashing is insecure**.
- Recognize why modern algorithms like **bcrypt** or **argon2** (with salting) are necessary.

#### Step 1: Setup Project

1. Create a new folder:
   ```bash
   mkdir rainbow-lab
   cd rainbow-lab
   ```
2. Initialize Node.js:
   ```bash
   npm init -y
   ```
3. No extra dependencies are needed — we’ll use Node’s built-in **crypto** library.

#### Step 2: Hashing Function

We’ll use SHA-256 to hash passwords. This is **unsalted**, meaning the same password always produces the same hash.

```js
const crypto = require("crypto");

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}
```

#### Step 3: Simulated Leaked Table

Imagine a database leak where only **username-hash pairs** are exposed (not the plain-text passwords).

```js
const leakedTable = [
  { username: "user1", hash: "741bfdda32c0281832bb6fb08a00c77a3f0d5fb05040abeff02313faa634e3a3" }, // p@ssword12345
  { username: "user2", hash: "fdfcc1d7c5352e52b288e75b8e91865d54132bd7398b99d7ce72f2ce6d2a2a2c" }, // R#wdf78>$12
  { username: "user3", hash: "f59ce04dd8baca6d6c47b45f24a87ddc7851f3b94762fe31b7a2e444c592028a" }, // Ilovecats
  { username: "user4", hash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" }, // admin
  { username: "user5", hash: "f4e98344541784f2eabcf6fcd1daf050afd9a1bfa2c59819356fe0543752f311" }, // Ab123456
];
```


#### Step 4: Attacker’s Dictionary

Attackers often use a **list of common passwords** (dictionary). If they hash each candidate and compare it to the leaked hashes, they can recover the original password.

```js
const possiblePasswords = [
  "letmein", "R#wdf78>$12", "abc123", "welcome", "dragon",
  "football", "sunshine", "whatever", "trustno1", "hello",
  "password123", "qwerty", "Ilovecats", "admin", "123456",
  "test", "guest", "password", "1234", "love", "qwertyuiop",
  "123123", "password1", "iloveyou", "123qwe", "1q2w3e4r",
  "welcome123", "letmein123",
];
```

#### Step 5: Simulate the Attack

We try each password in the dictionary, hash it, and compare it to the leaked hashes.

```js
function recoverPasswords(leakedTable, possiblePasswords) {
  const recovered = [];

  leakedTable.forEach((entry) => {
    for (const password of possiblePasswords) {
      const hashAttempt = hashPassword(password);
      if (hashAttempt === entry.hash) {
        recovered.push({ username: entry.username, matchedPassword: password });
        break; // Stop once the correct password is found
      }
    }
  });

  return recovered;
}

const recoveredPasswords = recoverPasswords(leakedTable, possiblePasswords);
```

#### Step 6: Output Results

```js
console.log("Leaked Table (Username-Hash Pairs):");
leakedTable.forEach((entry) =>
  console.log(`Username: ${entry.username}, Hash: ${entry.hash}`)
);

console.log("\nRecovered Passwords:");
recoveredPasswords.forEach((rec) =>
  console.log(`Recovered: ${rec.username}'s password is "${rec.matchedPassword}"`)
);

console.log("\nNote: if we use bcrypt or argon2 with salting, this attack is not possible.");
```

### Key Concepts Recap

- **Rainbow Table Attack**: Attackers precompute hashes of common passwords and compare them to leaked hashes.
- **Unsalted Hashing is Weak**: Same password → same hash. Easy to match with precomputed tables.
- **Salting**: Adding random data before hashing ensures that even identical passwords produce different hashes.
- **Modern Algorithms**: Use bcrypt, scrypt, or argon2 with salting and multiple iterations to resist rainbow table attacks.


### Exercise

1. Run the program and observe which passwords are recovered.  
2. Add more passwords to the dictionary and see if you can recover additional ones.  
3. Reflect: Why is storing plain SHA-256 hashes unsafe?  
4. Modify the code to use **bcrypt** and see how salting prevents this attack.  


### Note

Attackers often use a **list of common passwords** (dictionary). If they hash each candidate and compare it to the leaked hashes, they can recover the original password.  

In practice, hackers don’t just try passwords one by one — they often build what’s called a **rainbow table**. A rainbow table is a large precomputed database where each entry contains:  

- The **plain-text password** (e.g., `"admin"`)  
- Its **hashed value** (e.g., `"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"`)  

This means that instead of hashing every guess during the attack, they can simply **look up the hash** in their table and instantly know the matching password.  

For example, an attacker’s rainbow table might look like this:  

| Plain-text Password | SHA-256 Hash |
|---------------------|------------------------------------------------------------------|
| admin               | 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 |
| 123456              | 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92 |
| Ilovecats           | f59ce04dd8baca6d6c47b45f24a87ddc7851f3b94762fe31b7a2e444c592028a |

With such a table, if a leaked database contains the hash `8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918`, the attacker can immediately see that the password was `"admin"`.  

This is why **unsalted hashing is insecure**: the same password always produces the same hash, so attackers can reuse their rainbow tables across different systems.  

---

## Ref
- [Rainbow Attack](./material/src/rainbow-table-attack)