const jwt = require('jsonwebtoken');
const { jwt: jwtConfig } = require('../config/authConfig');

/**
 * Generate a JSON Web Token (JWT) for a user.
 * @param {Object} user - The user object containing user details like id, email, role.
 * @returns {string} - The generated JWT token.
 */
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },  
    jwtConfig.secret, 
    { expiresIn: jwtConfig.expiresIn }  
  );
};

/**
 * Verify a JSON Web Token (JWT) and extract the user information.
 * @param {string} token - The JWT token to verify.
 * @returns {Object} - The decoded token if valid, otherwise throws an error.
 */
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, jwtConfig.secret);  // Verifies and decodes the JWT
    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

/**
 * Extract the JWT from the Authorization header.
 * @param {Object} req - The Express request object.
 * @returns {string|null} - The JWT if found, otherwise null.
 */
const extractTokenFromHeader = (req) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');  
  return token || null;
};

module.exports = {
  generateToken,
  verifyToken,
  extractTokenFromHeader,
};
