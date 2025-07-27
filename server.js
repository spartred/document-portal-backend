// Import necessary modules
const express = require('express');
const { Pool } = require('pg'); // PostgreSQL client
const bcrypt = require('bcrypt'); // Password hashing library
const cors = require('cors'); // CORS middleware

// Initialize Express app
const app = express();
const port = 3000; // The port your backend server will listen on

// Middleware
app.use(express.json()); // To parse JSON request bodies
app.use(cors()); // Enable CORS for all origins (for development only, restrict in production)

// PostgreSQL Connection Pool Configuration
// IMPORTANT: Replace with your actual PostgreSQL credentials
const pool = new Pool({
    user: 'postgres', // e.g., 'postgres'
    host: 'localhost',
    database: 'postgres', // The database you created
    password: '5432', // Your PostgreSQL superuser or user password
    port: 5432, // Default PostgreSQL port
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    client.query('SELECT NOW()', (err, result) => {
        release();
        if (err) {
            return console.error('Error executing query', err.stack);
        }
        console.log('Successfully connected to PostgreSQL:', result.rows[0].now);
    });
});

// --- API Endpoints ---

// Register User Endpoint
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const passwordHash = await bcrypt.hash(password, salt);

        const result = await pool.query(
            'INSERT INTO users (email, password_hash, salt) VALUES ($1, $2, $3) RETURNING id',
            [email, passwordHash, salt]
        );

        res.status(201).json({ message: 'User registered successfully!', userId: result.rows[0].id });
    } catch (error) {
        console.error('Error during registration:', error);
        if (error.code === '23505') {
            return res.status(409).json({ message: 'Email already exists.' });
        }
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});


// Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            res.status(200).json({ message: 'Login successful!' });
        } else {
            res.status(401).json({ message: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

// NEW: Endpoint to get document details from the document_details table
app.get('/documents/:country/:type', async (req, res) => {
    const { country, type } = req.params; // Get country and type from the URL parameters

    try {
        // Query the document_details table
        const result = await pool.query(
            'SELECT * FROM document_details WHERE country = $1 AND document_type = $2',
            [country, type]
        );

        const document = result.rows[0]; // Get the first (and only) matching document

        if (document) {
            res.status(200).json(document); // Send the document data back to the frontend
        } else {
            res.status(404).json({ message: 'Document not found for the specified country and type.' });
        }
    } catch (error) {
        console.error('Error fetching document details:', error);
        res.status(500).json({ message: 'Internal server error fetching document details.' });
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Backend server running at http://localhost:${port}`);
});