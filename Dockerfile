# syntax=docker/dockerfile:1.7
FROM node:24-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
RUN mkdir -p /app/data /app/uploads && chown -R node:node /app
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
