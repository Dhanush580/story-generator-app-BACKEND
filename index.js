const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();
const app = express();
app.use(cors());
app.use(bodyParser.json());
const authRoutes = require('./routes/auth');
app.use('/api', authRoutes);
mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log('Connected to MongoDB');
    app.listen(5000, () => console.log('Server running on https://story-generator-app-backend.onrender.com'));
}).catch(err => console.log(err));
