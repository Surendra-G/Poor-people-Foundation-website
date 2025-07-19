// backend/server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const pool = require('./database/db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// Helper function to hash sensitive data
function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(bodyParser.json());

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/signup', async (req, res) => {
  // console.log("Signup request received"); 
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;

    // Validate input
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
      console.log('Missing required fields');
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      console.log('Passwords do not match');
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (password.length < 8) {
      console.log('Password must be at least 8 characters');
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if email exists
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      console.log('Email already in use');
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const [result] = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)',
      [firstName, lastName, email, hashedPassword]
    );

    res.status(201).json({
      message: 'User created successfully',
      userId: result.insertId
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//login route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = users[0];

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create JWT token (optional)
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );

    // Return user data (without password) and token
    const userData = {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email
    };

    res.status(200).json({
      message: 'Login successful',
      user: userData,
      token: token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//update Profile Section from the settings page
// Get user bio
app.get('/api/user/bio', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query(`
      SELECT u.id, u.first_name, u.last_name, u.email, b.bio 
      FROM users u
      LEFT JOIN bios b ON u.id = b.user_id
      WHERE u.email = ?
    `, [req.user.email]);

    if (result.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = {
      id: result[0].id,
      firstName: result[0].first_name,
      lastName: result[0].last_name,
      email: result[0].email,
      bio: result[0].bio || ''
    };

    res.json(userData);
  } catch (error) {
    console.error('Get bio error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user bio
app.put('/api/user/bio', authenticateToken, async (req, res) => {
  try {
    const { bio } = req.body;

    // First check if bio exists for user
    const [checkBio] = await pool.query(
      'SELECT * FROM bios WHERE user_id = (SELECT id FROM users WHERE email = ?)',
      [req.user.email]
    );

    if (checkBio.length > 0) {
      // Update existing bio
      await pool.query(
        'UPDATE bios SET bio = ? WHERE user_id = (SELECT id FROM users WHERE email = ?)',
        [bio, req.user.email]
      );
    } else {
      // Insert new bio
      await pool.query(
        'INSERT INTO bios (user_id, bio) VALUES ((SELECT id FROM users WHERE email = ?), ?)',
        [req.user.email, bio]
      );
    }

    res.json({ message: 'Bio updated successfully' });
  } catch (error) {
    console.error('Update bio error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update password
app.put('/api/user/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both current and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }

    // Get user's current password
    const [users] = await pool.query(
      'SELECT id, password FROM users WHERE email = ?',
      [req.user.email]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, users[0].password);
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await pool.query(
      'UPDATE users SET password = ? WHERE id = ?',
      [hashedPassword, users[0].id]
    );

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Get all blogs
app.get('/api/blogs', async (req, res) => {
  try {
    const [blogs] = await pool.query('SELECT * FROM blogs ORDER BY date DESC');
    
    // Parse JSON reviews and calculate average rating
    const formattedBlogs = blogs.map(blog => {
      const reviews = JSON.parse(blog.reviews || '[]');
      const averageRating = reviews.length > 0 
        ? reviews.reduce((sum, review) => sum + review.rating, 0) / reviews.length
        : 0;
      
      return {
        ...blog,
        reviews,
        average_rating: averageRating,
        review_count: reviews.length,
        date: new Date(blog.date).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        })
      };
    });
    
    res.json(formattedBlogs);
  } catch (error) {
    console.error('Error fetching blogs:', error);
    res.status(500).json({ error: 'Failed to fetch blogs' });
  }
});

// Get a single blog with reviews
app.get('/api/blogs/:id', async (req, res) => {
  try {
    const [blogs] = await pool.query('SELECT * FROM blogs WHERE id = ?', [req.params.id]);
    
    if (blogs.length === 0) {
      return res.status(404).json({ error: 'Blog not found' });
    }
    
    const [reviews] = await pool.query('SELECT * FROM blog_reviews WHERE blog_id = ?', [req.params.id]);
    
    const blog = {
      ...blogs[0],
      date: new Date(blogs[0].date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      }),
      reviews: reviews.map(review => ({
        ...review,
        date: new Date(review.created_at).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        })
      }))
    };
    
    res.json(blog);
  } catch (error) {
    console.error('Error fetching blog:', error);
    res.status(500).json({ error: 'Failed to fetch blog' });
  }
});

// Create a new blog
app.post('/api/blogs', async (req, res) => {
  try {
    const { title, description, category, image_url, content } = req.body;
    
    const [result] = await pool.query(
      'INSERT INTO blogs (title, description, category, image_url, content, date) VALUES (?, ?, ?, ?, ?, CURDATE())',
      [title, description, category, image_url, content]
    );
    
    const [newBlog] = await pool.query('SELECT * FROM blogs WHERE id = ?', [result.insertId]);
    
    res.status(201).json({
      ...newBlog[0],
      date: new Date(newBlog[0].date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      }),
      reviews: []
    });
  } catch (error) {
    console.error('Error creating blog:', error);
    res.status(500).json({ error: 'Failed to create blog' });
  }
});


// Add a review to a blog
app.post('/api/blogs/:id/reviews', async (req, res) => {
  try {
    const { author, rating } = req.body;
    
    // Validate rating
    if (typeof rating !== 'number' || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be a number between 1 and 5' });
    }

    const newReview = {
      id: Date.now(),
      author: author || 'Anonymous',
      rating: Number(rating),
      date: new Date().toLocaleDateString()
    };

    // console.log('New review:', newReview);

    // Get current reviews
    const [blogs] = await pool.query('SELECT reviews FROM blogs WHERE id = ?', [req.params.id]);
    const currentReviews = blogs[0]?.reviews ? JSON.parse(blogs[0].reviews) : [];
    
    // Add new review
    const updatedReviews = [...currentReviews, newReview];
    
    // Update the blog
    await pool.query(
      'UPDATE blogs SET reviews = ? WHERE id = ?',
      [JSON.stringify(updatedReviews), req.params.id]
    );

    // Calculate new average
    const averageRating = updatedReviews.reduce((sum, review) => sum + review.rating, 0) / updatedReviews.length;
    // console.log('New average rating:', averageRating);
    res.status(201).json({
      reviews: updatedReviews,
      average_rating: averageRating,
      review_count: updatedReviews.length
    });

  } catch (error) {
    console.error('Error adding review:', error);
    res.status(500).json({ error: 'Failed to add review' });
  }
});


// Create a new donation
app.post('/api/donations', async (req, res) => {
    try {
        const { amount, frequency, email, cardInfo, cardholderName, country } = req.body;
        
        // Basic validation
        if (!amount || !email || !cardInfo || !cardholderName || !country) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Get last 4 digits of card
        const lastFour = cardInfo.cardNumber.slice(-4);
        
        // Start transaction
        const conn = await pool.getConnection();
        await conn.beginTransaction();

        try {
            // Insert donation record
            const [donationResult] = await conn.query(
                'INSERT INTO Donations (amount, frequency, email, card_last_four, cardholder_name, country) VALUES (?, ?, ?, ?, ?, ?)',
                [amount, frequency, email, lastFour, cardholderName, country]
            );

            // Insert payment method (with hashed sensitive data)
            await conn.query(
                'INSERT INTO PaymentMethods (donation_id, card_type, card_number_hash, expiry_month, expiry_year, cvv_hash) VALUES (?, ?, ?, ?, ?, ?)',
                [
                    donationResult.insertId,
                    cardInfo.cardType || 'visa',
                    hashData(cardInfo.cardNumber),
                    cardInfo.expiryMonth,
                    cardInfo.expiryYear,
                    hashData(cardInfo.cvv)
                ]
            );

            await conn.commit();
            conn.release();

            res.status(201).json({
                message: 'Donation processed successfully',
                donationId: donationResult.insertId
            });
        } catch (err) {
            await conn.rollback();
            conn.release();
            throw err;
        }
    } catch (error) {
        console.error('Error processing donation:', error);
        res.status(500).json({ error: 'Failed to process donation' });
    }
});


// Get a single donation by ID
app.get('/api/donations/:id', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Donations WHERE id = ?', [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Donation not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching donation:', error);
        res.status(500).json({ error: 'Failed to fetch donation' });
    }
});


// Get donations by email
// app.get('/api/donations', async (req, res) => {
//     try {
//         const { email } = req.query;
//         console.log('Fetching donations for email:', email);
//         if (!email) {
//             return res.status(400).json({ error: 'Email parameter is required' });
//         }

//         // Verify token (optional but recommended for security)
//         const token = req.headers.authorization?.split(' ')[1];
//         if (!token) {
//             return res.status(401).json({ error: 'Unauthorized' });
//         }

//         // In a real app, you would verify the token and check if the requested email matches the token's email

//         const [rows] = await pool.query(
//             'SELECT id, amount, frequency, card_last_four, created_at FROM Donations WHERE email = ? ORDER BY created_at DESC',
//             [email]
//         );

//         res.json(rows);
//         console.log('Donations fetched successfully:', rows);
//     } catch (error) {
//         console.error('Error fetching donations:', error);
//         res.status(500).json({ error: 'Failed to fetch donations' });
//     }
// });


app.get('/api/donations', async (req, res) => {
    try {
        const { email } = req.query;
        // console.log('Fetching donations for email:', email);
        
        if (!email) {
            return res.status(400).json({ error: 'Email parameter is required' });
        }

        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // Debug: Show all tables in database
        const [tables] = await pool.query('SHOW TABLES');
        console.log('Database tables:', tables);

        // Debug: Show first 5 donations regardless of email
        const [sampleDonations] = await pool.query('SELECT email, amount FROM Donations LIMIT 5');
        console.log('Sample donations:', sampleDonations);

        const [rows] = await pool.query(
            'SELECT id, amount, frequency, card_last_four, created_at FROM Donations WHERE email = ? ORDER BY created_at DESC',
            [email]
        );

        // console.log('Query executed. Found', rows.length, 'donations');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching donations:', error);
        res.status(500).json({ error: 'Failed to fetch donations' });
    }
});

// Volunteer Opportunities
app.get('/api/opportunities', async (req, res) => {
  try {
    // In a real app, you might fetch these from a database
    const opportunities = [
      {
        title: 'Food Distribution Volunteer',
        desc: 'Help pack and distribute food to families in need at our community centers.',
        time: 'Weekday mornings (9am-12pm)',
        location: 'Downtown Center'
      },
      {
        title: 'Shelter Support Staff',
        desc: 'Assist with check-ins, meal service, and overnight monitoring at our shelters.',
        time: 'Evenings and weekends',
        location: 'Multiple locations'
      },
      {
        title: 'Tutoring & Mentoring',
        desc: 'Work with children and youth to provide academic support and guidance.',
        time: 'After-school hours',
        location: 'Education Center'
      },
      {
        title: 'Event Coordination',
        desc: 'Help plan and execute fundraising and awareness events.',
        time: 'Flexible',
        location: 'Main Office'
      }
    ];
    res.json(opportunities);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/volunteers', async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      interest,
      availability,
      experience
    } = req.body;

    // Basic validation
    if (!firstName || !lastName || !email || !phone || !interest || !availability) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const [result] = await pool.execute(
      `INSERT INTO volunteers 
      (first_name, last_name, email, phone, interest_area, availability, experience)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [firstName, lastName, email, phone, interest, availability, experience || null]
    );

    res.status(201).json({
      message: 'Volunteer application submitted successfully',
      id: result.insertId
    });
  } catch (err) {
    console.error(err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});




// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});