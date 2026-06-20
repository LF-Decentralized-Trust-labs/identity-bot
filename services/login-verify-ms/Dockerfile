FROM node:22-alpine AS build
WORKDIR /app
COPY packages/login-verify/package.json packages/login-verify/package-lock.json ./packages/login-verify/
COPY packages/login-verify/tsconfig.json ./packages/login-verify/
COPY packages/login-verify/src ./packages/login-verify/src/
COPY packages/login-verify/golden_vectors.json ./packages/login-verify/
RUN cd packages/login-verify && npm ci && npm run build

COPY services/login-verify-ms/package.json services/login-verify-ms/package-lock.json ./services/login-verify-ms/
COPY services/login-verify-ms/tsconfig.json ./services/login-verify-ms/
COPY services/login-verify-ms/src ./services/login-verify-ms/src/
RUN cd services/login-verify-ms && npm ci && npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8091
ENV HOST=0.0.0.0
COPY --from=build /app/packages/login-verify ./packages/login-verify
COPY --from=build /app/services/login-verify-ms ./services/login-verify-ms
WORKDIR /app/services/login-verify-ms
EXPOSE 8091
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8091/health || exit 1
CMD ["node", "dist/server.js"]