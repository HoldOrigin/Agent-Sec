FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentinel ./cmd/server

FROM alpine:3.22
WORKDIR /app
RUN addgroup -S sentinel && adduser -S -G sentinel sentinel
COPY --from=build /out/sentinel /usr/local/bin/sentinel
COPY public ./public
COPY datasets ./datasets
COPY opa ./opa
ENV PORT=8080
EXPOSE 8080
USER sentinel
ENTRYPOINT ["sentinel"]
CMD ["-root", "/app"]
