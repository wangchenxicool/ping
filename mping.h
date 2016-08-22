#include <stdio.h>  
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/time.h>

#define DNS_PORT 53
#define DNS_IP	"202.96.134.133"
#define DNS_IP02	"8.8.8.8"
#define DNS_IP03	"114.114.114.114"
#define MAX_DOMAINNAME_LEN  255
#define LOOP -1

// ICMP数据头结构  
typedef struct Icmp
{
	unsigned char type;       	//类型
	unsigned char code;			//代码
	unsigned short check_sum;	//检验和
	unsigned short id;			//标识符
	unsigned short seq;			//序列号
}IcmpHeader;

  
// IP数据包头结构  
typedef struct iphdr   
{  
    unsigned int headLen:4;   		//首部长度
    unsigned int version:4;  		//版本
    unsigned char tos;  			//区分服务
    unsigned short totalLen;  		//总长度
    unsigned short ident;  			//标识
    unsigned short fragAndFlags;  	//标志与片偏移
    unsigned char ttl;  			//生存时间
    unsigned char proto;  			//协议
    unsigned short checkSum;  		//检验和
    unsigned int sourceIP;  		//源地址
    unsigned int destIP;  			//目的地址
	
}IpHeader;  

typedef struct DNSheader
{
	unsigned short id;
	unsigned char  qr_opcode_aa_tc_rd;	//QR:0代表标准查询，1代表反向查询，2代表服务器状态请求
	unsigned char  ra_zero_rcode;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
	
}DnsHeader;


typedef struct Ipaddr
{
	 unsigned short len;
	 unsigned char a;
	 unsigned char b;
	 unsigned char c;
	 unsigned char d; 
}Ipadr;




// 计算ICMP包的校验和(发送前要用)  
unsigned short get_checkSum(unsigned short *buf, int size);
// 填充ICMP请求包的具体参数  
void pack_icmp(char *icmp_data, int size);
// 对返回的IP数据包进行解析，定位到ICMP数据 
int parse_respone(char *buf, int bytes , const char *ip, int recv_time);
// 计算最长返回时间
int max(int times[], int n);
// 计算最短返回时间
int min(int times[], int n);
// 计算返回时间的平均值
int average(int times[], int n);
//开始计时
int start_timer(struct timeval *stv);
//结束计时
int stop_timer(struct timeval *stv);
//执行ping功能
int ping(const char *ip,  int send_count);
//把域名打包成dns数据报的数据部分
int pack_name(char *data,const char *netname, int name_len);
//执行dns功能
int get_dns(const char *netname, char *buf, int name_len, int size, char *get_ip);







