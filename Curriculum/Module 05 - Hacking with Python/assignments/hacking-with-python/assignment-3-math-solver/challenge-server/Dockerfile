FROM python:3.11-slim

WORKDIR /app

# Copy challenge server
COPY challenge-server.py /app/

# Expose port
EXPOSE 9999

# Set environment variable
ENV FLAG="FLAG{Automation_Beats_Manual_Every_Time}"

# Run the server
CMD ["python", "challenge-server.py"]
