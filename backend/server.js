const express = require("express");
const dotenv = require("dotenv");
const { MongoClient } = require("mongodb");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
dotenv.config();
const { ObjectId } = require("mongodb");

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(text) {
  if (!text) return "";
  try {
    const [ivHex, encryptedHex] = text.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY),
      iv
    );
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error("Decryption error:", error);
    return "";
  }
}

const url = process.env.MONGO_URI;
const client = new MongoClient(url);

client
  .connect()
  .then(() => {
    console.log("Database connected");
  })
  .catch((error) => {
    console.error("Database connection failed:", error);
    process.exit(1);
  });

const dbName = process.env.DB_NAME;
const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());

const errorHandler = (error, req, res, next) => {
  console.error("Error:", error);
  res.status(500).json({ success: false, message: "Internal Server Error" });
};

app.use(errorHandler);

//get password by id
app.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const db = client.db(dbName);
    const collection = db.collection("passwords");
    const password = await collection.findOne({ _id: new ObjectId(id) });
    if (password) {
      password.password = password.displayPassword
        ? decrypt(password.displayPassword)
        : "";
      delete password.displayPassword;
      delete password.hashedPassword;
      res.status(200).json({ password });
    } else {
      res.status(404).json({ success: false, message: "Password not found" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// get all the passwords
app.get("/", async (req, res) => {
  try {
    const db = client.db(dbName);
    const collection = db.collection("passwords");
    const passwords = await collection.find({}).toArray();

    const decryptedPasswords = passwords.map((pwd) => ({
      _id: pwd._id,
      site: pwd.site,
      username: pwd.username,
      password: pwd.displayPassword ? decrypt(pwd.displayPassword) : "", // Handle missing displayPassword
      createdAt: pwd.createdAt,
    }));

    res.status(200).json(decryptedPasswords);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// save a password
app.post("/", async (req, res) => {
  try {
    const { site, username, password } = req.body;
    if (!password) {
      return res
        .status(400)
        .json({ success: false, message: "Password is required" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const displayPassword = encrypt(password);

    const db = client.db(dbName);
    const collection = db.collection("passwords");
    const result = await collection.insertOne({
      site,
      username,
      hashedPassword,
      displayPassword,
      createdAt: new Date(),
    });
    res.status(201).json({ success: true, result });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res
        .status(400)
        .json({ success: false, message: "ID is required" });
    }

    const db = client.db(dbName);
    const collection = db.collection("passwords");
    const result = await collection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Password not found" });
    }

    res.status(200).json({
      success: true,
      message: "Password deleted successfully",
      result,
    });
  } catch (error) {
    console.error("Error deleting password:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`server listening on http://localhost:${port}`);
});
