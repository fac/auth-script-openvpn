ARG DISTRIBUTION=ubuntu
ARG TAG=bionic
FROM $DISTRIBUTION:$TAG

RUN apt-get update && \
  apt-get upgrade -y && \
  apt-get install -y \
  lsb-release \
  openvpn \
  build-essential

RUN mkdir -p /opt/vpnauth
WORKDIR /opt/vpnauth
COPY . /opt/vpnauth

RUN make