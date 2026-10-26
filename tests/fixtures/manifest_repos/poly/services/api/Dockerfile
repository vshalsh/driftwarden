# syntax=docker/dockerfile:1
ARG DOTNET_VERSION=8.0
ARG REGISTRY=mcr.microsoft.com

FROM --platform=$BUILDPLATFORM ${REGISTRY}/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /out

FROM node:20-alpine AS assets
COPY --from=build /out /out

FROM mcr.microsoft.com/dotnet/aspnet:8.0@sha256:1111111111111111111111111111111111111111111111111111111111111111
COPY --from=build /out /app
COPY --from=nginx:1.25 /etc/nginx/nginx.conf /etc/nginx/nginx.conf
ENTRYPOINT ["dotnet", "/app/Api.dll"]
