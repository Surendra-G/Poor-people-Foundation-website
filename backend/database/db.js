// backend/database/db.js
require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'kandoo_foundation',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    console.log('Successfully connected to the database');

    // Create users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Create bios table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS bios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        bio TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY (user_id)
      )
    `);

    //For Blog posts
    await connection.query(`
      CREATE TABLE IF NOT EXISTS blogs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        content LONGTEXT,
        date DATE NOT NULL,
        category VARCHAR(50) NOT NULL,
        image_url VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    //For Donations
    await connection.query(`
  CREATE TABLE IF NOT EXISTS Donations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    amount DECIMAL(10, 2) NOT NULL,
    frequency ENUM('one-time', 'monthly', 'quarterly', 'yearly') NOT NULL,
    email VARCHAR(255) NOT NULL,
    card_last_four VARCHAR(4) NOT NULL,
    cardholder_name VARCHAR(255) NOT NULL,
    country VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'completed'
  )
`);

    //Create table for payment methods
    await connection.query(`
  CREATE TABLE IF NOT EXISTS PaymentMethods (
    id INT AUTO_INCREMENT PRIMARY KEY,
    donation_id INT NOT NULL,
    card_type VARCHAR(50) NOT NULL,
    card_number_hash VARCHAR(255) NOT NULL,
    expiry_month INT NOT NULL,
    expiry_year INT NOT NULL,
    cvv_hash VARCHAR(255) NOT NULL,
    FOREIGN KEY (donation_id) REFERENCES Donations(id) ON DELETE CASCADE
  )
`);

//create table for volunteer opportunities
await connection.query(`
  CREATE TABLE IF NOT EXISTS volunteers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(50) NOT NULL,
  last_name VARCHAR(50) NOT NULL,
  email VARCHAR(100) NOT NULL,
  phone VARCHAR(20) NOT NULL,
  interest_area VARCHAR(50) NOT NULL,
  availability TEXT NOT NULL,
  experience TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_email (email)
)
`);


    // Add reviews column to blogs table if it doesn't exist
    await connection.query(`
      ALTER TABLE blogs 
      ADD COLUMN IF NOT EXISTS reviews JSON DEFAULT '[]'
    `);




    connection.release();
    console.log('Database tables initialized');
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
}

initializeDatabase();

module.exports = pool;