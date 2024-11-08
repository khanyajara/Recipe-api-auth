const { roles } = require('../config/authConfig');


const hasRole = (requiredRoles) => {
  return (req, res, next) => {
   
    if (!req.user || !req.user.role) {
      return res.status(403).json({ message: 'Access denied. No role found.' });
    }

    
    if (!requiredRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
    }

    next(); 
  };
};

module.exports = hasRole;
