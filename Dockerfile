# syntax=docker/dockerfile:1.7
# DELIBERATELY VULNERABLE benchmark app - lab use only.
FROM node:24-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
# GROUND_TRUTH.json, scripts/ and the README are NOT copied: the scanner must not see the answers.
RUN mkdir -p /app/data /app/uploads && chown -R node:node /app
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
