FROM python:3.8

WORKDIR /app
COPY app  /app

# 创建 /etc 目录（如果不存在）
#RUN mkdir -p /etc/pip 

# 创建或替换 /etc/pip.conf 文件，并添加配置
#RUN echo "[global]" > /etc/pip/pip.conf && \
#    echo "index-url = https://mirrors.aliyun.com/pypi/simple/" >> /etc/pip/pip.conf

RUN pip install  -r requirements.txt  --index-url https://mirrors.aliyun.com/pypi/simple/

EXPOSE 5000

ENTRYPOINT ["python", "/app/app.py"]
