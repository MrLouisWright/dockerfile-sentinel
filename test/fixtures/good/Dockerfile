# syntax=docker/dockerfile:1
FROM node:22-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build
WORKDIR /src
COPY package*.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:1111111111111111111111111111111111111111111111111111111111111111
COPY --from=build /src/dist /app
USER 65532
HEALTHCHECK CMD ["/nodejs/bin/node", "/app/health.js"]
CMD ["/app/server.js"]
