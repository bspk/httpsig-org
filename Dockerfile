# syntax = docker/dockerfile:1.3

FROM --platform=$BUILDPLATFORM node:18.16.0-alpine3.17 AS frontend-builder
ENV NODE_OPTIONS=--openssl-legacy-provider
RUN apk add autoconf automake libtool make tiff jpeg zlib zlib-dev pkgconf nasm file gcc musl-dev util-linux && yarn global add gatsby-cli && gatsby telemetry --disable
WORKDIR /build
COPY frontend/package.json frontend/yarn.lock ./
RUN npx browserslist@latest --update-db && yarn
COPY frontend/. ./
RUN yarn build

FROM alpine:3.17 AS backend
ENV PYTHONUNBUFFERED=1
RUN apk add python3 py3-pip python3-dev gcc musl-dev libffi-dev make
WORKDIR /backend
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt
COPY backend/. ./
COPY --from=frontend-builder /build/public/. /frontend
CMD ["gunicorn", "-b 0.0.0.0:8000", "handler:app"]
