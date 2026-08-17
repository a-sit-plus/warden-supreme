# syntax=docker/dockerfile:1
FROM ghcr.io/cirruslabs/android-sdk:36 AS sources

RUN apt-get update \
    && apt-get install --yes --no-install-recommends openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY . .
RUN git init --quiet dependencies/android-key-attestation \
    && git -C dependencies/android-key-attestation remote add origin https://github.com/google/android-key-attestation.git \
    && git -C dependencies/android-key-attestation fetch --depth 1 origin f9846cd019289f1788cec65b062d9f81c0c4884c \
    && git -C dependencies/android-key-attestation checkout --detach FETCH_HEAD \
    && git init --quiet dependencies/http-proxy \
    && git -C dependencies/http-proxy remote add origin https://github.com/zk-123/http-proxy.git \
    && git -C dependencies/http-proxy fetch --depth 1 origin b5eb132640649154f8b3d59f530070161490f92e \
    && git -C dependencies/http-proxy checkout --detach FETCH_HEAD \
    && git init --quiet dependencies/keyattestation \
    && git -C dependencies/keyattestation remote add origin https://github.com/android/keyattestation.git \
    && git -C dependencies/keyattestation fetch --depth 1 origin 47f970d044ae4da7b00da068e7e1a4e952b0fd2f \
    && git -C dependencies/keyattestation checkout --detach FETCH_HEAD \
    && git init --quiet release-1.0.2 \
    && git -C release-1.0.2 remote add origin https://github.com/a-sit-plus/warden-supreme.git \
    && git -C release-1.0.2 fetch --depth 1 origin a1bca5c87edfd586ad9cc71f499fe91b1bdb6643 \
    && git -C release-1.0.2 checkout --detach FETCH_HEAD \
    && git -C release-1.0.2 submodule update --init --recursive --depth 1 --jobs 4 \
    && test -z "$(git -C dependencies/android-key-attestation status --porcelain)" \
    && test -z "$(git -C dependencies/http-proxy status --porcelain)" \
    && test -z "$(git -C dependencies/keyattestation status --porcelain)" \
    && test -z "$(git -C release-1.0.2 status --porcelain)"

FROM sources AS build
RUN --mount=type=cache,target=/root/.gradle \
    if [ -f .env ]; then \
        while IFS='=' read -r key value; do \
            case "$key" in \
                BASE_URL|COLLECTOR_KEYSTORE_PATH|COLLECTOR_KEYSTORE_PASSWORD|COLLECTOR_KEY_ALIAS|COLLECTOR_KEY_PASSWORD) export "$key=$value" ;; \
            esac; \
        done < .env; \
    fi; \
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
