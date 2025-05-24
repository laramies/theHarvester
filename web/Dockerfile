# Base Node image
FROM node:20-alpine

# Set working directory
WORKDIR /app/web

# Copy package.json and lock file
COPY package.json package-lock.json* npm-shrinkwrap.json* ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the Next.js application
RUN npm run build

# Expose port and command
EXPOSE 3000
CMD ["npm", "start"]
