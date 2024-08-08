const express = require('express');
const morgan = require('morgan');
require('dotenv').config();
const indexrouter = require('./routes/routes')
const index = require('./routes/index')
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');


const app = express();
app.use(morgan('dev'));
app.use(express.json());

// app.use('/uploads', express.static('uploads'));

// Ensure the uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Serve static files from the uploads directory
app.use('/uploads', express.static(uploadsDir));



const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));
const allowedOrigins = [
    'http://localhost:3002',
    'https://messenger-users.vercel.app/login',
    'https://messenger-users.vercel.app'

  ];

  const corsOptions = {
    origin: function (origin, callback) {
      // Allow requests with no origin, like mobile apps or curl requests
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        const msg = 'The CORS policy for this site does not allow access from the specified origin.';
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true
  };
  
  app.use(cors(corsOptions));



// Define a route for the root URL
app.use('/api', indexrouter);





const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});