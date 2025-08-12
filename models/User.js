const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  googleId: { 
    type: String, 
    required: true, 
    unique: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true 
  },
  name: { 
    type: String, 
    required: true 
  },
  profilePicture: {
    type: String,
    default: null
  },
  accessToken: {
    type: String,
    required: true
  },
  refreshToken: {
    type: String,
    default: null
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastLogin: { 
    type: Date, 
    default: Date.now 
  },
  preferences: {
    language: {
      type: String,
      default: 'en'
    },
    theme: {
      type: String,
      enum: ['light', 'dark'],
      default: 'light'
    }
  }
}, {
  timestamps: true
});

// Indexes are already created via unique: true in schema definition

// Virtual for user's full profile
userSchema.virtual('profile').get(function() {
  return {
    id: this._id,
    googleId: this.googleId,
    name: this.name,
    email: this.email,
    profilePicture: this.profilePicture,
    preferences: this.preferences,
    lastLogin: this.lastLogin
  };
});

// Method to update last login
userSchema.methods.updateLastLogin = function() {
  this.lastLogin = new Date();
  return this.save();
};

module.exports = mongoose.model('User', userSchema);