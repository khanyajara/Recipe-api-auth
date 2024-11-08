require('dotenv').config();

module.exports = {
  jwt: {
    secret: process.env.JWT_SECRET,     
    expiresIn: '1h',                     
  },
  session: {
    secret: process.env.SESSION_SECRET,   
    resave: false,                        
    saveUninitialized: false,            
    cookie: {
      secure: process.env.NODE_ENV === 'production',  
      httpOnly: true,                    
      maxAge: 3600000                    
    }
  },
  roles: {
    admin: ['create', 'edit', 'delete'],  
    user: ['view'],                       
  }
};
