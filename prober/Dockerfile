# 独立发包端：仅用 Python 标准库，不需要 nftables/特权
FROM python:3.12-slim

WORKDIR /prober
COPY prober.py /prober/prober.py

# 不申请 NET_ADMIN / NET_RAW：它只向外发起普通 TCP 连接
EXPOSE 9000
CMD ["python", "-u", "/prober/prober.py"]
