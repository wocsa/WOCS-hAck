# Use an official Python runtime as a parent image
FROM python:3.9.18-alpine3.18

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY ./website/wocshack3 /app

# Install any needed packages
RUN pip install --upgrade pip
RUN pip install django Pillow djangorestframework-simplejwt lxml pyjwt

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launches
CMD ["python", "manage.py", "runserver", "0.0.0.0:80"]
