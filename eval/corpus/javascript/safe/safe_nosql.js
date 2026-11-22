const User = require("./models/User");

function handleSafeSearch(req, res) {
    User.find({ username: String(req.body.username) }).then((users) => res.json(users));
}
