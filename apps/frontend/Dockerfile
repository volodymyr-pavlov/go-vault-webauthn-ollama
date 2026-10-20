# check=skip=InvalidDefaultArgInFrom
# The page on nginx. The build context is the repository root.
ARG NODE_ALPINE_IMAGE
ARG NGINX_IMAGE

FROM ${NODE_ALPINE_IMAGE} AS build

WORKDIR /src/apps/frontend

COPY apps/frontend/package.json apps/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY apps/frontend/ ./

# VITE_MAIL_URL is where the page points to the mail of the stand. Empty leaves the hint out.
ARG VITE_MAIL_URL=
ENV VITE_MAIL_URL=${VITE_MAIL_URL}
RUN npm run build

FROM ${NGINX_IMAGE}

ARG VERSION=0.0.0-dev
ARG SOURCE_URL=https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama

LABEL org.opencontainers.image.title="go-vault-webauthn-ollama-frontend" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.source="${SOURCE_URL}"

# BACKEND_URL is where /v1/ goes. DNS_RESOLVER finds it: the resolver of Docker by default, and the one of the
# cluster in Kubernetes.
ENV BACKEND_URL=http://backend:8080 \
	DNS_RESOLVER=127.0.0.11

COPY apps/frontend/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY apps/frontend/nginx-security.inc /etc/nginx/security.inc
COPY apps/frontend/nginx-proxy.inc /etc/nginx/proxy.inc
COPY --from=build /src/apps/frontend/.dist /usr/share/nginx/html

# The official image starts nginx as root, and nginx then drops to the nginx user. Here nginx runs as that user from the
# start, as the documentation of the image describes. The config has no `user` directive and puts the pid file in /tmp.
# The nginx user owns the directories that nginx and the entrypoint write to: the cache, and the config that the
# template becomes.
RUN sed -i '/^user /d; s,/run/nginx.pid,/tmp/nginx.pid,' /etc/nginx/nginx.conf \
	&& chown -R nginx:nginx /var/cache/nginx /etc/nginx/conf.d

USER nginx

EXPOSE 8080/tcp

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
