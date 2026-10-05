# =============================================================
#  Certificate DApp - Docker image
#
#  Build:
#      docker build -t certificate-app .
#
#  Run:
#      docker run -p 5000:5000 --env-file .env certificate-app
#  Or use docker-compose.yml
# =============================================================

# ---------- Stage 1: build the React frontend ----------
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# ---------- Stage 2: runtime (Express + built frontend) ----------
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV DATA_DIR=/app/data

# copy runtime deps only (avoid devDependencies)
COPY package*.json ./
RUN npm install --omit=dev

# copy the built frontend from stage 1 + server sources
COPY --from=build /app/build ./build
COPY server.js ./
COPY db.js ./
# include a config template so volumes / env can be set up easily
COPY .env.example ./env.example

# writable data dir for certificates.json + activity.json
RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://localhost:5000/api/dashboard/stats').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" || exit 1

CMD ["node", "server.js"]