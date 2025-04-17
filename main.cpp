#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <sstream>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

unordered_set<string> blocklist;

void usage() {
    printf("syntax : netfilter-test <site list file>\n");
    printf("sample : netfilter-test top-1m.txt\n");
}

void store_hashlist(const string& filename){
    ifstream file(filename);
    if(!file.is_open()){
        cout << "failed open file" << endl;
    }

    string line;
    while(getline(file, line)){
        stringstream ss(line);
        string n, site;

        if(getline(ss, n, ',') && getline(ss, site)){
            blocklist.insert(site);
        }
    }
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
    }

    fputc('\n', stdout);

    return id; //!mal_site
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    printf("Entering callback\n");

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);
    struct iphdr *ip = (struct iphdr *)payload;
    if(ip->protocol == IPPROTO_TCP){
        int ip_header_len = ip->ihl*4;
        struct tcphdr *tcp = (struct tcphdr *)(payload + ip_header_len);
        int tcp_header_len = tcp->doff*4;
        unsigned char *http_data = payload + ip_header_len + tcp_header_len;
        int http_data_len = len - ip_header_len - tcp_header_len;

        int prefix_len = strlen("Host: ");
        for(int i=0; i<len-prefix_len; i++){
            if(strncmp((const char*)&http_data[i], "Host: ", prefix_len) == 0){
                char *host = (char*)&http_data[i+prefix_len];
                char *end = strstr(host, "\r\n");
                if(end)
                {
                    *end = '\0';
                    printf("[+] Host: %s\n", host);

                    if(blocklist.find(host) != blocklist.end()){
                        printf("DROP packet\n");
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        printf("argc: %d\n", argc);
        usage();
        return EXIT_FAILURE;
    }

    const char* filename = argv[1];
    store_hashlist(filename);

    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(EXIT_FAILURE);
    }

    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(EXIT_FAILURE);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(EXIT_FAILURE);
    }

    printf("Binding this socket to queue '1'\n");
    qh = nfq_create_queue(h, 1, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(EXIT_FAILURE);
    }

    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(EXIT_FAILURE);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("Packet received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("Losing packets!\n");
            continue;
        }
        perror("Recv failed");
        break;
    }

    printf("Unbinding from queue 1\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("Unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("Closing library handle\n");
    nfq_close(h);

    exit(EXIT_SUCCESS);
}



