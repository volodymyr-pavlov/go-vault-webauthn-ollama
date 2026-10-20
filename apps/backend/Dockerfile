# check=skip=InvalidDefaultArgInFrom
# The backend: one static binary on a minimal image, run as nobody. The build context is the repository root.
ARG GO_ALPINE_IMAGE
ARG ALPINE_IMAGE

FROM ${GO_ALPINE_IMAGE} AS build

WORKDIR /src/apps/backend

COPY apps/backend/go.mod apps/backend/go.sum ./
RUN go mod download

COPY apps/backend/ ./

ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/server ./cmd/server \
	&& CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/evaluate ./cmd/evaluate \
	&& CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/recovery ./cmd/recovery

FROM ${ALPINE_IMAGE} AS runtime

ARG VERSION=0.0.0-dev
ARG SOURCE_URL=https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama

LABEL org.opencontainers.image.title="go-vault-webauthn-ollama-backend" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.source="${SOURCE_URL}"

RUN apk add --no-cache ca-certificates

COPY --from=build /out/server /out/evaluate /out/recovery /usr/local/bin/

USER nobody

EXPOSE 8080/tcp

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- --header='User-Agent: healthcheck' http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["server"]
