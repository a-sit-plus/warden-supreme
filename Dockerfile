# syntax=docker/dockerfile:1
FROM ghcr.io/cirruslabs/android-sdk:36 AS build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY . .
RUN mkdir -p .git/objects .git/refs \
    && git config core.repositoryformatversion 0 \
    && git config remote.origin.url https://github.com/a-sit-plus/warden-supreme.git \
    && git submodule update --init --recursive --force \
    && git submodule foreach --recursive 'test -z "$(git status --porcelain)"'
RUN --mount=type=cache,target=/root/.gradle \
    ./gradlew --no-daemon --max-workers=2 \
    -Dorg.gradle.jvmargs="-Xmx2g -XX:MaxMetaspaceSize=768m" \
    :collector-backend:buildFatJar

FROM eclipse-temurin:17-jre-jammy

RUN useradd --system --uid 10001 collector \
    && mkdir /attetations \
    && chown collector /attetations
WORKDIR /app
COPY --from=build /workspace/collector/backend/build/libs/collector-backend-all.jar app.jar

ENV OUTPUT_DIR=/attetations
EXPOSE 8080
USER collector
ENTRYPOINT ["java", "-jar", "app.jar"]
