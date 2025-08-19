# Use a lightweight Nginx image to serve the static content
FROM nginx:alpine

# Copy the HTML file into the Nginx public directory
# The file must be named index.html for Nginx to serve it by default
COPY docker_files/index.html /usr/share/nginx/html/

# Expose port 80, which is the default for Nginx
EXPOSE 80

# Nginx will automatically start and serve the file when the container runs
CMD ["nginx", "-g", "daemon off;"]



