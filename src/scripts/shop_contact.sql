CREATE TABLE shop_contacts (
    contact_id SERIAL PRIMARY KEY,
    shop_id INT REFERENCES shops(shop_id) ON DELETE CASCADE,
    contact_email VARCHAR(50),
    contact_phone VARCHAR(50) NOT NULL,
    contact_facebook VARCHAR(50),
    contact_lines VARCHAR(50),
    contact_tiktok VARCHAR(50),
    contact_instagram VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by VARCHAR(50),
    updated_by VARCHAR(50)
);