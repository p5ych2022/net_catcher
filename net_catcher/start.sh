#!/bin/bash
# 无限循环，每隔五秒执行一次 ./c/http_app "eth0" "live"
while true
do
  ./c/http_app "eth0" "live"
  sleep 150
done
