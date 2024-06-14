CREATE TABLE shops (
    shop_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    image_url VARCHAR(255),
    name VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    latitude VARCHAR(50) NOT NULL,
    longtitude VARCHAR(50) NOT NULL,
     created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by VARCHAR(50),
    updated_by VARCHAR(50)
);