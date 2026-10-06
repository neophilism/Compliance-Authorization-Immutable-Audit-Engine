FROM node:20-bookworm-slim AS build

WORKDIR /app

ARG CAIAE_API_BASE_URL=http://localhost:4000
ENV CAIAE_API_BASE_URL=$CAIAE_API_BASE_URL

COPY . .
RUN npm install
RUN npm run build

FROM node:20-bookworm-slim AS api

WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=node:node /app /app

USER node

EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["npm", "run", "start", "-w", "@caiae/api"]

FROM node:20-bookworm-slim AS worker

WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=node:node /app /app

USER node

CMD ["npm", "run", "start", "-w", "@caiae/worker"]

FROM node:20-bookworm-slim AS web

WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=node:node /app /app

USER node

EXPOSE 3000
CMD ["npm", "run", "start", "-w", "@caiae/web"]
