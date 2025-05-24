# Base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app/api

# Install Poetry
RUN pip install poetry

# Copy Poetry config and lock file
COPY pyproject.toml poetry.lock* ./

# Install project dependencies
# --no-root is used because we only want to install dependencies, not the project itself as editable
RUN poetry install --no-root --no-dev

# Copy the rest of the application code
COPY . .

# Expose port and command (will be overridden by docker-compose for dev)
EXPOSE 8000
CMD ["poetry", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
