-- ========================================================
-- PHISHGUARD: Phishing Attack Detection & Awareness System
-- Student: Chauhan Brijesh Ramayan
-- Mentor: Jagruti Raut
-- College Mini Project
-- Database Schema for MySQL / MariaDB
-- ========================================================

CREATE DATABASE IF NOT EXISTS phishguard_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishguard_db;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. URL Scans Table
CREATE TABLE IF NOT EXISTS url_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    url TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    passed_count INT DEFAULT 0,
    concern_count INT DEFAULT 0,
    indicators_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 3. Email Scans Table
CREATE TABLE IF NOT EXISTS email_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    sender VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    body_snippet TEXT,
    risk_score INT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    concern_count INT DEFAULT 0,
    indicators_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 4. Quiz Results Table
CREATE TABLE IF NOT EXISTS quiz_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    score INT NOT NULL,
    total_questions INT NOT NULL,
    percentage DECIMAL(5, 2) NOT NULL,
    performance_rating VARCHAR(50) NOT NULL,
    answers_json TEXT,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 5. Activity Logs Table
CREATE TABLE IF NOT EXISTS activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    activity_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
