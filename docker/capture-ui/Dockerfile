FROM node:20-slim

WORKDIR /app
COPY ui/capture/package*.json ./
RUN npm ci

EXPOSE 4202
# Source is bind-mounted at runtime; node_modules stays in the image layer.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
