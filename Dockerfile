# Use the official Rust image as the builder stage
FROM rust:slim-buster as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install OpenSSL development packages
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy over your application source code
COPY . .

# Build the application (assuming it's in debug mode for now)
RUN cargo build

# For the final stage, use a smaller base image
FROM debian:bullseye-slim

# Install necessary libraries. Adjust based on your application's requirements
RUN apt-get update && apt-get install -y libpq5 libssl1.1 && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the built executable from the builder stage to the final image
COPY --from=builder /usr/src/app/target/debug/weed_vibe /usr/local/bin/weed_vibe

# Expose port 8080 (if your application listens on this port)
EXPOSE 8080

# Set the start command
CMD ["/usr/local/bin/weed_vibe"]
