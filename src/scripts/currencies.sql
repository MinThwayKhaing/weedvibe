CREATE TABLE currencies (
    currency_id SERIAL PRIMARY KEY,
    code VARCHAR(10) NOT NULL UNIQUE,  -- e.g., 'USD', 'EUR'
    name VARCHAR(50) NOT NULL,         -- e.g., 'US Dollar', 'Euro'
    symbol VARCHAR(10) NOT NULL        -- e.g., '$', '€'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by VARCHAR(50),
    updated_by VARCHAR(50)
);