# VulnAI DevSecOps - React Frontend
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Use Nginx to serve the built static resources
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose standard port
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
