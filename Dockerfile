FROM rust:1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --user-group --home-dir /nonexistent llmfw
COPY --from=builder /app/target/release/llm-firewall /usr/local/bin/llm-firewall
COPY config.example.yaml /etc/llm-fw/config.yaml
USER llmfw
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/llm-firewall", "--config", "/etc/llm-fw/config.yaml"]
