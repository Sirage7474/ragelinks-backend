const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB connection with better error handling
mongoose.connect('mongodb://localhost:27017/ragelinks', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('Connected to MongoDB');
})
.catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
});

// Add error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    settings: {
        bgColor1: String,
        bgColor2: String,
        titleColor1: String,
        titleColor2: String,
        cursorUrl: String
    },
    links: [{
        name: String,
        url: String
    }]
});

const User = mongoose.model('User', userSchema);

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            username,
            password: hashedPassword,
            settings: {
                bgColor1: '#1a1a1a',
                bgColor2: '#2d2d2d',
                titleColor1: '#ff6b6b',
                titleColor2: '#4ecdc4',
                cursorUrl: ''
            },
            links: []
        });

        await user.save();
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: error.message || 'Error creating user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) return res.status(400).send('User not found');
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid password');

        const token = jwt.sign({ username: user.username }, 'your-secret-key');
        res.json({ token });
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        res.json({
            settings: user.settings,
            links: user.links
        });
    } catch (error) {
        res.status(500).send('Error fetching user data');
    }
});

app.put('/api/user/settings', authenticateToken, async (req, res) => {
    try {
        await User.updateOne(
            { username: req.user.username },
            { $set: { settings: req.body } }
        );
        res.send('Settings updated');
    } catch (error) {
        res.status(500).send('Error updating settings');
    }
});

app.post('/api/user/links', authenticateToken, async (req, res) => {
    try {
        await User.updateOne(
            { username: req.user.username },
            { $push: { links: req.body } }
        );
        res.send('Link added');
    } catch (error) {
        res.status(500).send('Error adding link');
    }
});

app.delete('/api/user/links/:index', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        user.links.splice(req.params.index, 1);
        await user.save();
        res.send('Link deleted');
    } catch (error) {
        res.status(500).send('Error deleting link');
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 