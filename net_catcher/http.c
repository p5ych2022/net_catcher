#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <resolv.h>
#include <string.h>
#include <mysql/mysql.h>
#include <iconv.h>

struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag : 3, iph_offset : 13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

void handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_data(const unsigned char *, unsigned int);
void write_HTML(const u_char *, int);
void store_in_db(const char *src_ip, const char *dst_ip, const char *protocol, const char *data);

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;
    int packet_count = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface/filename> <mode>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *source = argv[1];
    char *mode = argv[2];

    if (strcmp(mode, "live") == 0) {
        handle = pcap_open_live(source, BUFSIZ, 1, 1000, errbuf);
    } else if (strcmp(mode, "file") == 0) {
        handle = pcap_open_offline(source, errbuf);
    } else {
        fprintf(stderr, "Invalid mode. Use 'live' for live capture or 'file' for reading from a file.\n");
        exit(EXIT_FAILURE);
    }

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open source %s: %s\n", source, errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    printf("Start capturing...\n");
    pcap_loop(handle, -1, handler, (unsigned char *)&packet_count);

    pcap_close(handle);
    return 0;
}

void write_HTML(const u_char *tcp_data, int tcp_data_len) {
    const u_char *body_start = NULL;
    for (int i = 0; i < tcp_data_len - 3; i++) {
        if (tcp_data[i] == '\r' && tcp_data[i + 1] == '\n' && tcp_data[i + 2] == '\r' && tcp_data[i + 3] == '\n') {
            body_start = tcp_data + i + 4;
            break;
        }
    }

    if (body_start) {
        int body_len = tcp_data_len - (body_start - tcp_data);

        char filename[64];
        sprintf(filename, "http_data.txt");
        FILE *fp = fopen(filename, "ab");
        if (fp == NULL) {
            fprintf(stderr, "Failed to open file '%s'", filename);
            return;
        }

        fwrite(body_start, 1, body_len, fp);
        fclose(fp);
        printf("HTTP data saved to file '%s'\n", filename);
    } else {
        printf("No HTTP body found in the packet\n");
    }
}

void handler(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet) {
    int *packet_count = (int *)args;
    (*packet_count)++;
    printf("*********************** Receive a packet ***********************\n");
    printf("Packet count: %d\n", *packet_count);

    struct ethheader *eth = (struct ethheader *)packet;

    printf("Source MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", eth->ether_shost[i]);
    }
    printf("\tDestination MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", eth->ether_dhost[i]);
    }
    printf("\nEthernet Type: %04x\n", ntohs(eth->ether_type));

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_len = ip->iph_ihl * 4;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        strcpy(src_ip, inet_ntoa(ip->iph_sourceip));
        strcpy(dst_ip, inet_ntoa(ip->iph_destip));

        printf("From: %s\t", src_ip);
        printf("To: %s\n", dst_ip);

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = tcp->th_off * 4;
            unsigned char *tcp_data = (unsigned char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
            int payload_length = hdr->len - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

            printf("Protocol: TCP\n");
            printf("From: %d\t", ntohs(tcp->source));
            printf("To: %d\n", ntohs(tcp->dest));

            if (payload_length > 0) {
                print_data(tcp_data, payload_length);

                // Handle HTTP and HTTPS (assuming port 443 for HTTPS)
                if (ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80) {
                    printf("HTTP Data:\n");
                    write_HTML(tcp_data, payload_length);
                } else if (ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443) {
                    printf("HTTPS Data (encrypted, not displaying content)\n");
                } else if (ntohs(tcp->source) == 21 || ntohs(tcp->dest) == 21) {
                    printf("FTP Data:\n");
                }

                store_in_db(src_ip, dst_ip, "TCP", (char *)tcp_data);
            } else {
                printf("No TCP payload\n");
            }

        } else if (ip->iph_protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethheader) + ip_header_len);
            unsigned char *udp_data = (unsigned char *)(packet + sizeof(struct ethheader) + ip_header_len + sizeof(struct udphdr));
            int payload_length = hdr->len - (sizeof(struct ethheader) + ip_header_len + sizeof(struct udphdr));

            printf("Protocol: UDP\n");
            printf("From: %d\t", ntohs(udp->uh_sport));
            printf("To: %d\n", ntohs(udp->uh_dport));

            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53) {
                printf("DNS Data:\n");
                ns_msg msg;
                if (ns_initparse(udp_data, payload_length, &msg) >= 0) {
                    ns_rr rr;
                    for (int i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
                        if (ns_parserr(&msg, ns_s_an, i, &rr) == 0) {
                            printf("DNS Answer: %s\n", ns_rr_name(rr));
                        }
                    }
                }
            }

            if (payload_length > 0) {
                print_data(udp_data, payload_length);
                store_in_db(src_ip, dst_ip, "UDP", (char *)udp_data);
            } else {
                printf("No UDP payload\n");
            }

        } else if (ip->iph_protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct ethheader) + ip_header_len);
            printf("Protocol: ICMP\n");
            printf("Type: %d\tCode: %d\n", icmp->type, icmp->code);
            store_in_db(src_ip, dst_ip, "ICMP", (char *)(packet + sizeof(struct ethheader) + ip_header_len + sizeof(struct icmphdr)));

        } else {
            printf("Protocol: Others\n");
        }
    } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        printf("Protocol: ARP\n");
    } else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) {
        printf("Protocol: IPV6\n");
    }
}

void print_data(const unsigned char *data, unsigned int len) {
    printf("Received %d bytes\n*************************** Payload ****************************\n", len);
    for (unsigned int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\t");
            for (unsigned int j = i - 15; j <= i; j++) {
                if (data[j] >= 32 && data[j] <= 126) {
                    printf("%c", data[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
    printf("\n");
}

int is_utf8(const char *string) {
    iconv_t cd = iconv_open("UTF-8", "UTF-8");
    if (cd == (iconv_t)-1) {
        return 0;
    }
    size_t inbytesleft = strlen(string);
    size_t outbytesleft = inbytesleft * 2;
    char *inbuf = (char *)string;
    char *outbuf = malloc(outbytesleft);
    if (!outbuf) {
        iconv_close(cd);
        return 0;
    }
    char *outptr = outbuf;
    size_t result = iconv(cd, &inbuf, &inbytesleft, &outptr, &outbytesleft);
    free(outbuf);
    iconv_close(cd);
    return result != (size_t)-1;
}

char *convert_to_utf8(const char *input) {
    iconv_t cd = iconv_open("UTF-8", "ISO-8859-1");
    if (cd == (iconv_t)-1) {
        return NULL;
    }
    size_t inbytesleft = strlen(input);
    size_t outbytesleft = inbytesleft * 2;
    char *outbuf = malloc(outbytesleft);
    if (!outbuf) {
        iconv_close(cd);
        return NULL;
    }
    char *inbuf = (char *)input;
    char *outptr = outbuf;
    size_t result = iconv(cd, &inbuf, &inbytesleft, &outptr, &outbytesleft);
    if (result == (size_t)-1) {
        free(outbuf);
        iconv_close(cd);
        return NULL;
    }
    *outptr = '\0';
    iconv_close(cd);
    return outbuf;
}

void store_in_db(const char *src_ip, const char *dst_ip, const char *protocol, const char *data) {
    MYSQL *conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mysql_real_connect(conn, "172.18.0.2", "ids", "1ds", "traffic_data", 0, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    if (mysql_set_character_set(conn, "utf8mb4") != 0) {
        fprintf(stderr, "mysql_set_character_set() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    const char *query = "INSERT INTO traffic (src_ip, dst_ip, protocol, payload) VALUES (?, ?, ?, ?)";

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt) {
        fprintf(stderr, "mysql_stmt_init() out of memory\n");
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
        fprintf(stderr, "mysql_stmt_prepare(), INSERT failed: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    char *utf8_data = NULL;
    if (!is_utf8(data)) {
        utf8_data = convert_to_utf8(data);
        if (!utf8_data) {
            fprintf(stderr, "Failed to convert data to UTF-8\n");
            mysql_stmt_close(stmt);
            mysql_close(conn);
            exit(EXIT_FAILURE);
        }
    } else {
        utf8_data = strdup(data);
        if (!utf8_data) {
            fprintf(stderr, "Failed to duplicate data\n");
            mysql_stmt_close(stmt);
            mysql_close(conn);
            exit(EXIT_FAILURE);
        }
    }

    MYSQL_BIND bind[4];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char *)src_ip;
    bind[0].buffer_length = strlen(src_ip);

    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char *)dst_ip;
    bind[1].buffer_length = strlen(dst_ip);

    bind[2].buffer_type = MYSQL_TYPE_STRING;
    bind[2].buffer = (char *)protocol;
    bind[2].buffer_length = strlen(protocol);

    bind[3].buffer_type = MYSQL_TYPE_BLOB;
    bind[3].buffer = utf8_data;
    bind[3].buffer_length = strlen(utf8_data);

    if (mysql_stmt_bind_param(stmt, bind)) {
        fprintf(stderr, "mysql_stmt_bind_param() failed: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        free(utf8_data);
        exit(EXIT_FAILURE);
    }

    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, "mysql_stmt_execute() failed: %s\n", mysql_stmt_error(stmt));
    }else{
        printf("Data stored in database: src_ip=%s, dst_ip=%s, protocol=%s\n", src_ip, dst_ip, protocol);        
    }

    mysql_stmt_close(stmt);
    free(utf8_data);
}
