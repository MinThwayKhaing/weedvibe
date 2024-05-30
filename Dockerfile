# Use a Rust base image
FROM rust:latest

# Set the working directory inside the container
WORKDIR /usr/src/weed_vibe

# Copy the project files to the container
COPY . .

# Build your application
RUN cargo build --release

# Set the startup command
CMD ["./target/release/weed_vibe"]
