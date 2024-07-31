const bcrypt = require('bcryptjs');
const { check, validationResult, body } = require('express-validator');
const session = require("express-session");
const express = require('express')
const router = express.Router();
const User = require('../model/user');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;


router.use(passport.initialize());
router.use(session({ secret: "cats", resave: true, saveUninitialized: true, cookie: { secure: true } }));
router.use(passport.session())




router.post('/sign-up', [

  body().custom(body => {
    if (Object.keys(body).length === 0) {
      throw new Error('No entries made in the sign-up form');
    }
    return true;
  }),

    check('firstName').notEmpty().withMessage('First name is required'),
    check('lastName').notEmpty().withMessage('Last name is required'),
    check('password')
      .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
      .matches(/[0-9]/).withMessage('Password must contain a number')
      .matches(/[@$!%*?&#]/).withMessage('Password must contain a special character'),
    check('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    const { firstName, lastName, password } = req.body;
    const username = `${firstName}${lastName}`.toLowerCase();
  
    try {

        // Check if the username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username is already taken' });
        }

      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Save the user to the database (pseudo code)
      // await User.create({ firstName, lastName, password: hashedPassword });

      const newUser = new User({
        firstName,
        lastName,
        username,
        password: hashedPassword,
      });
  
      await newUser.save();
  
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });


  router.post('/login', [
    check('username').notEmpty().withMessage('Username is required'),
    check('password').notEmpty().withMessage('Password is required')
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    const { username, password } = req.body;
  
    try {
      // Find the user by username
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(400).json({ error: 'Invalid username or password' });
      }
  
      // Compare the password with the hashed password in the database
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid username or password' });
      }
  
      // If login is successful
      res.status(200).json({ message: 'Login successful' });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  

// Signout route
router.post('/logout', (req, res) => {
  req.logout((err) => {
      if (err) {
          return res.status(500).json({ error: 'Failed to log out' });
      }
      res.status(200).json({ message: 'Logged out successfully' });
  });
});


passport.use(new LocalStrategy(
  { usernameField: 'username' }, // Use email as the username field
  async (username, password, done) => {
      try {
          // Find user by email
          const user = await User.findOne({ username });
          if (!user) {
              return done(null, false, { message: 'No user with that username' });
          }

          // Compare provided password with stored hashed password
          const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) {
              return done(null, false, { message: 'Password incorrect' });
          }

          // Authentication successful
          return done(null, user);
      } catch (err) {
          return done(err);
      }
  }
));



// Serialize user to store user ID in session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
      const user = await User.findById(id);
      done(null, user);
  } catch (err) {
      done(err);
  }
});
module.exports = router;

  module.exports = router;