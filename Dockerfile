# Use an official Python runtime as a parent image.
FROM python:3.10-slim

# Set environment variables to avoid .pyc files and enable unbuffered logging.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container.
WORKDIR /app

# Copy the requirements file into the container.
COPY requirements.txt .

# Install any needed packages specified in requirements.txt.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the container.
COPY . .

# Expose the port the app runs on. Adjust if you change the port.
EXPOSE 8443

# Define the default command to run your server.
CMD ["python", "server.py"]


