CREATE TABLE products (
    product_id SERIAL PRIMARY KEY,
    image_url VARCHAR(255),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    shop_id INT REFERENCES shops(shop_id),
    category_id INT REFERENCES categories(category_id),
    currency_id INT REFERENCES currencies(currency_id),
    price DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by VARCHAR(50),
    updated_by VARCHAR(50)
);