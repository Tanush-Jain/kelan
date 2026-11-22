const User = require("./models/User");

function handleSearch(req, res) {
    // NoSQL injection passing unsanitized body directly into find
    User.find(req.body).then((users) => res.json(users));
}
