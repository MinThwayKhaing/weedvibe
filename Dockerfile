# Use the official Rust image as the base image
FROM rust:latest

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files to the working directory
COPY Cargo.toml Cargo.lock ./

# Copy the entire project directory to the working directory
COPY . .

# Build the Rust project
RUN cargo build --release

# Set the startup command for the container
CMD ["./target/release/weedvibe"]
