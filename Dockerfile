# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/authserver ./cmd/authserver

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 authserver \
    && adduser -S -D -H -u 10001 -G authserver authserver
COPY --from=build /out/authserver /usr/local/bin/authserver
USER 10001:10001
EXPOSE 5175
ENTRYPOINT ["authserver"]
CMD ["serve"]
