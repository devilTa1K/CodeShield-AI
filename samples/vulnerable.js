const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");

const app = express();
const API_KEY = "sk_live_example_not_a_real_key_1234";

app.get("/search", (req, res) => {
  const sql = "SELECT * FROM products WHERE name = '" + req.query.q + "'";
  db.query(sql, (err, rows) => res.send("<h1>Results for " + req.query.q + "</h1>"));
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

document.getElementById("out").innerHTML = location.hash.slice(1);
