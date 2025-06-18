const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Story = require('../models/story');


const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid token.' });
  }
};
router.post('/signup', async (req, res) => {
    const { name, email, password, securityQuestion, securityAnswer } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedAnswer = await bcrypt.hash(securityAnswer, 10); // Secure the answer

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            securityQuestion,
            securityAnswer: hashedAnswer
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err });
    }
});


router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.status(200).json({ 
            message: 'Login successful',
            token,
            user: { name: user.name, email: user.email }
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});
router.post('/story', authenticate, async (req, res) => {
  try {
    const { prompt, story } = req.body;
    const newStory = new Story({ user: req.userId, prompt, story });
    await newStory.save();
    res.status(201).json({ message: 'Story saved successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error saving story' });
  }
});
router.get('/mystories', authenticate, async (req, res) => {
  try {
    const stories = await Story.find({ user: req.userId }).sort({ createdAt: -1 });
    res.json(stories);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching stories' });
  }
});
router.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching profile', error: err.message });
  }
});
router.put('/profile', authenticate, async (req, res) => {
  try {
    const { name, password, profilePic } = req.body;
    const update = {};

    if (name) update.name = name;
    if (profilePic) update.profilePic = profilePic;
    if (password) update.password = await bcrypt.hash(password, 10);

    await User.findByIdAndUpdate(req.userId, update);
    res.json({ message: "Profile updated" });
  } catch (err) {
    res.status(500).json({ message: 'Error updating profile', error: err.message });
  }
});
router.get('/get-security-question', async (req, res) => {
  try {
    const { email } = req.query;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ securityQuestion: user.securityQuestion });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});
router.post('/reset-password', async (req, res) => {
  try {
    const { email, securityAnswer, newPassword } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isAnswerCorrect = await bcrypt.compare(securityAnswer, user.securityAnswer);

    if (!isAnswerCorrect) {
      return res.status(401).json({ message: 'Incorrect answer to security question' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    await user.save();

    return res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
