FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY fragnesia_breakout.c /build/
RUN gcc -O2 -Wall -Wextra -static -o /build/fragnesia_breakout /build/fragnesia_breakout.c

FROM ubuntu:24.04
COPY --from=builder /build/fragnesia_breakout /fragnesia_breakout
RUN chmod +x /fragnesia_breakout
USER 1000
ENTRYPOINT ["/fragnesia_breakout"]
