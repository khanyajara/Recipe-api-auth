const jwt = require('jsonwebtoken');
const { jwt: jwtConfig } = require('../config/authConfig');


const isAuthenticated = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ message: 'Authorization token required' });
  }

  try {
    const decoded = jwt.verify(token, jwtConfig.secret);
    req.user = decoded; 
    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const hasRole = (roles) => {
  return (req, res, next) => {
    const { role } = req.user;

    if (!roles.includes(role)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    next(); 
  };
};

module.exports = {
  isAuthenticated,
  hasRole,
};
