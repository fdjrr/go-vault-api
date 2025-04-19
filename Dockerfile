FROM golang:1.24-alpine AS builder

RUN apk add --no-cache 

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o app .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/app .

CMD ["./app"]