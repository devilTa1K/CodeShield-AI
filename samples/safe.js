const express = require("express");
const crypto = require("crypto");

const app = express();
const API_KEY = process.env.API_KEY;

app.get("/search", async (req, res) => {
  const rows = await db.query("SELECT id, name FROM products WHERE name = $1", [req.query.q]);
  res.json(rows);
});

function hashPassword(pw, salt) {
  return crypto.scryptSync(pw, salt, 64).toString("hex");
}

document.getElementById("out").textContent = location.hash.slice(1);
