const bcrypt = require('bcryptjs');
const { check, validationResult, body } = require('express-validator');
const session = require("express-session");
const express = require('express')
const router = express.Router();
const User = require('../model/user');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const secretKey = 'ADMIN';
const jwt = require('jsonwebtoken');
const Token = require('../model/token');
const Message = require('../model/message');
const homeData = require('../config/homeData')
const multer = require('multer');
const path = require('path');




router.use(passport.initialize());
router.use(session({ secret: "cats", resave: true, saveUninitialized: true, cookie: { secure: true } }));
router.use(passport.session())




const verifyToken = async (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
      return res.status(401).json({ message: 'No token provided' });
  }

  try {
      const decoded = jwt.verify(token, secretKey);
      const tokenRecord = await Token.findOne({ token });

      if (!tokenRecord) {
          return res.status(401).json({ message: 'Invalid token' });
      }

      req.userId = decoded.id;
      next();
  } catch (error) {
      return res.status(401).json({ message: 'Unauthorized' });
  }
};

// Set storage engine
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });


// Check file type
function checkFileType(file, cb) {
  const filetypes = /jpeg|jpg|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
}


// Serve static files from the "uploads" directory
const app = express();
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
  ], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    passport.authenticate('local', async (err, user, info) => {
      if (err) return next(err);
      if (!user) return res.status(400).json({ error: info.message });
  
      req.logIn(user, async (err) => {
        if (err) return next(err);
  
        const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
  
        try {
          await Token.create({ token, userId: user._id });
          return res.status(200).json({ message: 'Login successful', user, token });
        } catch (error) {
          return res.status(500).json({ message: 'Error saving token' });
        }
      });
    })(req, res, next);
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

router.get('/check-auth', verifyToken, (req, res) => {
  res.status(200).json({ message: 'Authenticated' });
});

router.get('/home', verifyToken, async (req, res, next) => { 
  return res.json({
      ...homeData,
      message: 'Your Login was successful'
    });
})


router.get('/users',verifyToken, async (req, res) => {
  try {
    const users = await User.find({}, 'firstName lastName'); // Fetch only firstName and lastName
    res.json(users);
  } catch (error) {
    res.status(500).send('Server error');
  }
});


router.get('/users/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId, 'firstName lastName username profilePicture facebookURL linkedInURL twitterURL githubPages aboutMe');
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.json(user);
  } catch (error) {
    res.status(500).send('Server error');
  }
});


router.put('/users/me', verifyToken, upload.single('profilePicture'), async (req, res) => {
  try {
    // Find user by ID from token
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).send('User not found');
    }

    // Update fields from request body
    const updates = ['firstName', 'lastName', 'username', 'facebookURL', 'linkedInURL', 'twitterURL', 'githubPages', 'aboutMe'];
    updates.forEach((field) => {
      if (req.body[field] !== undefined) {
        user[field] = req.body[field];
      }
    });

    // If there's a new profile picture, update it
    if (req.file) {
      user.profilePicture = req.file.path; // Store the path of the uploaded file
    }

    // Save the updated user
    await user.save();

    // Respond with the updated user data (excluding sensitive information)
    res.json({
      firstName: user.firstName,
      lastName: user.lastName,
      username: user.username,
      profilePicture: user.profilePicture,
      facebookURL: user.facebookURL,
      linkedInURL: user.linkedInURL,
      twitterURL: user.twitterURL,
      githubPages: user.githubPages,
      aboutMe: user.aboutMe,
    });
  } catch (error) {
    res.status(500).send('Server error');
  }
});





// Get messages between the current user and a specified user
router.get('/messages/:receiverId', verifyToken, async (req, res) => {
  try {
    const { receiverId } = req.params;
    const messages = await Message.find({
      $or: [
        { sender: req.userId, receiver: receiverId },
        { sender: receiverId, receiver: req.userId },
      ],
    }).sort('createdAt');
    res.json(messages);
  } catch (error) {
    res.status(500).send('Server error');
  }
});



router.get('/messages/:userId', async (req, res) => {
  const userId = req.params.userId;
  const currentUserId = req.userId; // Get the current user's ID from the request

  try {
    const messages = await Message.find({
      $or: [
        { sender: currentUserId, receiver: userId },
        { sender: userId, receiver: currentUserId }
      ]
    }).populate('sender', 'username').populate('receiver', 'username'); // Populate sender and receiver usernames

    res.json(messages);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Send a message to a specified user
router.post('/messages/:receiverId', verifyToken, async (req, res) => {
  try {
    const { receiverId } = req.params;
    const { text } = req.body;

    const message = await Message.create({
      sender: req.userId,
      receiver: receiverId,
      text,
    });

    res.status(201).json(message);
  } catch (error) {
    res.status(500).send('Server error');
  }
});

// router.post('/messages/:receiverId', async (req, res) => {
//   const { text } = req.body;
//   const senderId = req.user._id; // Get the current user's ID from the request
//   const receiverId = req.params.receiverId;

//   try {
//     const newMessage = new Message({
//       text,
//       sender: senderId,
//       receiver: receiverId
//     });

//     await newMessage.save();
//     res.status(201).json(newMessage);
//   } catch (err) {
//     res.status(500).json({ message: err.message });
//   }
// });








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