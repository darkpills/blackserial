# syntax=docker/dockerfile:1

# Building dependencies

FROM debian:bookworm AS builder

WORKDIR /build/

ENV DEBIAN_FRONTEND=noninteractive

# Install APT packages
RUN apt update -y && apt install -y git maven python3 python3-requests nodejs wget unzip

COPY archives .
COPY install.sh .

RUN bash ./install.sh

# Target image

FROM debian:bookworm

# Copy project files to image

WORKDIR /app

RUN sed -i -e's/ main/ main contrib non-free/g' /etc/apt/sources.list.d/debian.sources
RUN dpkg --add-architecture i386
RUN apt update -y && apt install -y --install-recommends mono-complete wine winetricks

RUN winetricks -q dotnet48
RUN winetricks -q nocrashdialog


COPY --from=builder /build/bin /app/
COPY blackserial.py /app/
COPY serializers /app/


ENTRYPOINT ["python3", "/app/blackserial.py"]

CMD ["--help"]


