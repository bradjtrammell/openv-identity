FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /openv-identity .

FROM alpine:3.20
RUN addgroup -S openv && adduser -S -G openv openv
COPY --from=build /openv-identity /usr/local/bin/openv-identity
RUN mkdir /data && chown openv:openv /data
USER openv
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/openv-identity", "-listen", "0.0.0.0:8088", "-data", "/data/identity.json"]
