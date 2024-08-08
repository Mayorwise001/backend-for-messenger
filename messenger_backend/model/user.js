// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,

  },
  password: {
    type: String,
    required: true,
  },
  profilePicture: {
    type: String, // URL to the profile picture
    default: '',
  },
  facebookURL: {
    type: String,
    default: '',
  },
  linkedInURL: {
    type: String,
    default: '',
  },
  twitterURL: {
    type: String,
    default: '',
  },
  githubURL: {
    type: String,
    default: '',
  },
  aboutMe: {
    type: String,
    default: '',
  },
});

module.exports = mongoose.model('User', userSchema);
