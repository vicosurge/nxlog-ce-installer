FROM alpine:3.18
MAINTAINER Vicente Munoz <vicente.mm.milchorena@gmail.com>

LABEL name="nxlog-ce" \
      maintainer="vicente.mm.milchorena@gmail.com" \
      vendor="NXLog Ltd" \
      version="CE 3.1.2319" \
      release="2" \
      summary="NXLog is a modular, multi-threaded, high-performance log management solution" \
      description="NXLog is a modular, multi-threaded, high-performance log management solution"

WORKDIR /tmp/nxlog
COPY . .
RUN apk add --no-cache bash
RUN ["/bin/bash", "nxlog_ce.sh"]
ENTRYPOINT ["nxlog", "-f"]
