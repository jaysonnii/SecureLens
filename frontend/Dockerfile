FROM node:24-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci

COPY . .

ARG VITE_API_URL=/api
ARG VITE_MAX_FILE_SIZE_MB=25

ENV VITE_API_URL=${VITE_API_URL}
ENV VITE_MAX_FILE_SIZE_MB=${VITE_MAX_FILE_SIZE_MB}

RUN npm run build


FROM nginx:alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=10s \
    --retries=3 \
    CMD wget -q -O - http://127.0.0.1/ || exit 1

