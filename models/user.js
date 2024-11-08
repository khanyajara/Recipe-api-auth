const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');


const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true, 
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address'], 
  },
  password: {
    type: String,
    required: true,
    minlength: 6, 
  },
  role: {
    type: String,
    enum: ['admin', 'user'], 
    default: 'user', 
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});


userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10); 
    this.password = await bcrypt.hash(this.password, salt); 
    next(); 
  } catch (error) {
    next(error); 
  }
});


userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);