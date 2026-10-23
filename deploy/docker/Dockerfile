# agentio server image. Build from the repository root:
#   docker build -f deploy/docker/Dockerfile --build-arg VERSION=… --build-arg REVISION=… -t agentio/server .
# It needs only protocol/ and server/, so it builds the same in the public server source.
# Cross-compile on the build machine's architecture rather than emulating the target.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS server
ARG VERSION=dev
ARG REVISION=unknown
ARG TARGETOS TARGETARCH
# The server module finds protocol/ through its replace directive; no workspace is involved.
ENV GOWORK=off
WORKDIR /src
COPY protocol/ protocol/
COPY server/go.mod server/go.sum server/
RUN cd server && go mod download
COPY server/ server/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -C server -trimpath \
    -ldflags "-s -w -X agentio.sh/server/internal/server.Version=${VERSION} -X agentio.sh/server/internal/server.Revision=${REVISION}" \
    -o /agentio-server ./cmd/agentio-server
# Distroless has no shell: create the data directory here so a fresh volume is owned by nonroot.
RUN mkdir /agentio-data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=server /agentio-server /usr/bin/agentio-server
COPY --from=server --chown=nonroot:nonroot /agentio-data /var/lib/agentio
ENV AGENTIO_DATA_DIR=/var/lib/agentio \
    AGENTIO_HTTP_ADDR=:2586
VOLUME /var/lib/agentio
EXPOSE 2586
USER nonroot
ENTRYPOINT ["/usr/bin/agentio-server"]
CMD ["serve"]
