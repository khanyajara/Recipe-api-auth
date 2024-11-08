const express = require('express');
const router = express.Router();
const authController = require('../controllers/authControllers');
const { validateRegistration } = require('../middleware/validateRegistration');
const { validateLogin } = require('../middleware/login');


router.post('/register', validateRegistration, authController.register);
router.post('/login', validateLogin, authController.login);


module.exports = router;
