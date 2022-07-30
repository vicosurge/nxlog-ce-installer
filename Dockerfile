FROM alpine:latest
MAINTAINER Vicente Munoz <vicente.mm.milchorena@gmail.com>

LABEL name="nxlog-ce" \
      maintainer="vicente.mm.milchorena@gmail.com" \
      vendor="NXLog Ltd" \
      version="CE 3.0.2272" \
      release="1" \
      summary="NXLog is a modular, multi-threaded, high-performance log management solution" \
      description="NXLog is a modular, multi-threaded, high-performance log management solution"

WORKDIR /tmp/nxlog
COPY . .
RUN /bin/ash nxlog_ce_installer.sh
ENTRYPOINT ["nxlog", "-f"]
