const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const jwtPassword = "12345678";
const zod = require("zod");

mongoose.connect("your mongodb connection string");

//db module
const userModel = mongoose.model("user", {
  email: { type: String, unique: true },
  username: String,
  password: String,
});

const app = express();
app.use(express.json());

//check if user email exists
async function userExists(email) {
  return await userModel.findOne({ email });
}

//signup schema
const signupSchema = zod.object({
  email: zod.string().email(),
  username: zod.string().min(3).max(20),
  password: zod.string().min(6).max(20),
});

//login schema
const loginSchema = zod.object({
  email: zod.string().email(),
  password: zod.string().min(6).max(20),
});

//validate signup request body
function validateSignup(req, res, next) {
  const parseData = signupSchema.safeParse(req.body);
  if (!parseData.success) {
    return res.status(400).json({
      msg: "Invalid inputs",
      errors: parseData.error.errors,
    });
  }
  req.body = parseData.data;
  next();
}

//validate login request body
function validateLogin(req, res, next) {
  //validate request body
  const parseData = loginSchema.safeParse(req.body);
  if (!parseData.success) {
    return res.status(400).json({
      msg: "Invalid inputs",
      errors: parseData.error.errors,
    });
  }
  req.body = parseData.data;
  next();
}

//for new user
app.post("/signup", async function (req, res) {
  try {
    const { email, username, password } = req.body;
    //checks if already exists
    if (await userExists(email)) {
      return res.status(400).json({ msg: "User already exixts in database" });
    }
    //stores data in database
    await userModel.create({
      email: email,
      username: username,
      password: password,
    });
    const token = jwt.sign({ email }, jwtPassword);
    res.json({ token });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ msg: "Email already exists." });
    }
    res.status(500).send(error);
  }
});

//if user already exists in database
app.post("/login", async function (req, res) {
  try {
    const { email, password } = req.body;
    const userProfile = await userExists(email);
    if (!userProfile) {
      return res.status(400).json({ msg: "User not found, please SignUp" });
    }
    if (userProfile.password !== password) {
      return res.status(403).json({ msg: "Incorrect Credentials" });
    }
    const token = jwt.sign({ email }, jwtPassword);
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ msg: "Something went wrong, try again later" });
  }
});

//to get all users excepting 'this' user
app.get("/users", async function (req, res) {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, jwtPassword);
    const email = decoded.email;
    const restUsers = await userModel.find({ email: { $ne: decoded.email } });
    return res.status(200).json(restUsers);
  } catch {
    return res.status(400).json({ msg: "Invalid token" });
  }
});

app.listen(3000, () => {
  console.log("Server started on port 3000");
});
