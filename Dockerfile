# Start from an official Python 3.10 image
FROM python:3.10-slim

# Install the C libraries needed to build mysqlclient AND the python dev headers
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file in first and install (this is cached)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code into the container
COPY . .

# Create the upload folder and set permissions
RUN mkdir -p /var/www/uploads && chown -R www-data:www-data /app /var/www/uploads

# Expose the port the app runs on
EXPOSE 5000

# Command to run your app as a non-root user
USER www-data
CMD ["flask", "run", "--host=0.0.0.0"]
