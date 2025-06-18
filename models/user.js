const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    profilePic: { type: String, default: "" },
    securityQuestion: String,
    securityAnswer: String
});

module.exports = mongoose.model('User', userSchema);
