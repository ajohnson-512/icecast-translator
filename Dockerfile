FROM golang:1.19 AS build

WORKDIR /go/cmd/icecast-translator

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/icecast-translator

FROM alpine:latest

WORKDIR /app
COPY --from=build /app/icecast-translator .

EXPOSE 8085

CMD ["./icecast-translator"]
