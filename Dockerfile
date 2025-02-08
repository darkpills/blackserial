# syntax=docker/dockerfile:1
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Copy project files to image
WORKDIR /app
COPY . .
RUN rm -rf ./bin/* *.cache

# Install packages
RUN sed -i -e's/ main/ main contrib non-free/g' /etc/apt/sources.list.d/debian.sources
RUN apt update -y && apt install -y \
    php \
    python3 \
    python3-pip \
    ruby \
    nodejs \
    npm \
    git \
    wget

# Install dependencies
RUN bash ./install.sh

ENTRYPOINT ["python3", "/app/blackserial.py"]

CMD ["--help"]


