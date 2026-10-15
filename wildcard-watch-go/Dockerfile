FROM golang:1.25-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY main.go ./
COPY seed_state.json ./
RUN CGO_ENABLED=0 go build -o /watch .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /watch /usr/local/bin/watch

# /data é onde o Volume do Railway é montado (guarda o estado entre
# execuções do cron) — mesmo volume já usado pela versão em Python.
ENV STATE_PATH=/data/seen_programs.json

CMD ["watch"]
