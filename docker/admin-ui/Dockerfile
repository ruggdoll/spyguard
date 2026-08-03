FROM node:20-slim

WORKDIR /app
COPY ui/admin/package*.json ./
RUN npm ci

EXPOSE 4201
# Source is bind-mounted at runtime; node_modules stays in the image layer.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
