FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# install golang
RUN apt-get update \
    && apt-get install -y git wget \
    && wget -P /tmp https://dl.google.com/go/go1.19.1.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf /tmp/go1.19.1.linux-amd64.tar.gz \
    && rm /tmp/go1.19.1.linux-amd64.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# install remaining dependencies
RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  sudo \
  python3 \
  vim \
  libgmp3-dev \
  libprocps-dev \
  libssl-dev \
  openjdk-17-jdk \
  junit4 \
  python3-markdown\
  libboost-program-options-dev \
  pkg-config

# copy cloned repo into container
RUN mkdir origo
COPY . origo/

# docker installer script
WORKDIR /root/origo/docker
# RUN pwd && ls
RUN ./install.sh

# compile go code
WORKDIR /root/origo/server
RUN go mod tidy
RUN go build server.go
WORKDIR ../proxy/service
RUN go mod tidy
RUN go build proxy.go
WORKDIR /root/origo
RUN go mod tidy
# RUN go build -buildvcs=false .
RUN go build .

EXPOSE 8080

# start command
CMD ["/bin/bash"]

# ARG SSH_PRIVATE_KEY
# RUN mkdir /root/.ssh/
# RUN echo "${SSH_PRIVATE_KEY}" > /root/.ssh/id_ed25519
# RUN touch /root/.ssh/known_hosts
# RUN ssh-keyscan gitlab.lrz.de >> ~/.ssh/known_hosts
# RUN ssh-keyscan github.com >> ~/.ssh/known_hosts
# RUN chmod 400 /root/.ssh/id_ed25519

