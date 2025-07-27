// Import necessary modules
const express = require('express');
const { Pool } = require('pg'); // PostgreSQL client
const bcrypt = require('bcrypt'); // Password hashing library
const cors = require('cors'); // CORS middleware

// Initialize Express app
const app = express();
const port = 3000; // The port your backend server will listen on (internally on Render)

// Middleware
app.use(express.json()); // To parse JSON request bodies
app.use(cors()); // Enable CORS for all origins (for development only, restrict in production)

// PostgreSQL Connection Pool Configuration
// IMPORTANT: This uses process.env.DATABASE_URL, which you set on Render's dashboard.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Render will provide this as an environment variable
    ssl: {
        rejectUnauthorized: false // Required for Render's SSL connection
    }
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        // Log the full error stack for debugging connection issues
        return console.error('Error acquiring client from pool:', err.stack);
    }
    client.query('SELECT NOW()', (err, result) => {
        release(); // Release the client back to the pool
        if (err) {
            return console.error('Error executing test query:', err.stack);
        }
        console.log('Successfully connected to PostgreSQL on Render:', result.rows[0].now);
    });
});

// --- API Endpoints ---

// Register User Endpoint
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Basic input validation
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const saltRounds = 10; // Cost factor for hashing (higher is slower but more secure)
        const salt = await bcrypt.genSalt(saltRounds); // Generate a unique salt for each user
        const passwordHash = await bcrypt.hash(password, salt); // Hash the password with the generated salt

        // Insert the new user into the 'users' table
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, salt) VALUES ($1, $2, $3) RETURNING id',
            [email, passwordHash, salt]
        );

        res.status(201).json({ message: 'User registered successfully!', userId: result.rows[0].id });
    } catch (error) {
        console.error('Error during registration:', error);
        // Handle specific PostgreSQL error for unique constraint violation (e.g., email already exists)
        if (error.code === '23505') {
            return res.status(409).json({ message: 'Email already exists. Please use a different email.' });
        }
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});


// Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Basic input validation
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        // Find the user by email in the 'users' table
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        // If user not found
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // Compare the provided password with the stored hashed password
        // bcrypt.compare() handles the salting automatically when comparing against a hash that includes its salt
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Login successful
            // In a real application, you would typically generate a JWT (JSON Web Token) here
            // and send it back to the client for subsequent authenticated requests.
            // For simplicity in this test, we'll just send a success message.
            res.status(200).json({ message: 'Login successful!' /*, token: 'your_jwt_token_here' */ });
        } else {
            // Passwords do not match
            res.status(401).json({ message: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

// Endpoint to get document details from the 'document_details' table
app.get('/documents/:country/:type', async (req, res) => {
    const { country, type } = req.params; // Extract country and document type from URL parameters

    try {
        // Query the 'document_details' table for the specific document
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
    console.log(`Backend server running on port ${port}`);
});