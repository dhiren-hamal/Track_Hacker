FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app source
COPY src ./src
COPY README.md ./
COPY env.example ./env.example

# Prepare runtime dirs
RUN mkdir -p /app/data && chown -R node:node /app

USER node
ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "src/index.js"]


