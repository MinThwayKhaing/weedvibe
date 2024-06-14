CREATE TABLE advertisements (
    ad_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    image_url VARCHAR(255),
    title VARCHAR(100) NOT NULL,
    content TEXT,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    period_time INTERVAL,
   created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by VARCHAR(50),
    updated_by VARCHAR(50)
);