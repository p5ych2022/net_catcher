FROM ubuntu:latest

# 安装必要的包和库
RUN apt-get update && apt-get install -y --fix-missing \
    build-essential \
    libpcap-dev \
    libmysqlclient-dev \
    libiconv-hook-dev \
    mysql-client \
    iptables \
    iputils-ping \
    libnet-dev 

WORKDIR /app

RUN mkdir  -p /app/c
COPY start.sh /start.sh
COPY http.c  /app/c/http.c

RUN chmod +x /start.sh

RUN gcc -o ./c/http_app  ./c/http.c -lpcap -lmysqlclient -lresolv

CMD ["/start.sh"]
#CMD ["./c/http_app", "eth0", "live"]
# CMD ["/bin/bash"]

