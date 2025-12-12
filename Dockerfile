# Use a Node.js runtime as the base image
FROM node:18.14.0-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the package.json and package-lock.json to the working directory
COPY package*.json ./

# Install project dependencies
RUN npm install

# Copy the entire project directory to the working directory in the container
COPY . .

# Expose the port your NestJS app is running on (change this to the actual port)
EXPOSE 5000

# Start the NestJS application
CMD [ "npm", "run", "start:dev" ]
