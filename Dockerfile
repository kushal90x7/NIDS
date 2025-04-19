FROM python:3.9-slim-bookworm

WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the NIDS application
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to run the NIDS
CMD ["python", "main.py"]