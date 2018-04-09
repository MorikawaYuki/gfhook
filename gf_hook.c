#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_bridge.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/icmp.h>
#include <linux/netfilter_ipv4.h>
#include "url_redirect.h"

struct sk_buff *tcp_newpack(u32 saddr, u32 daddr,

                            u16 sport, u16 dport,

                            u32 seq, u32 ack_seq,

                            u8 *msg, int len);

int _tcp_send_pack(struct sk_buff *skb, struct iphdr *iph,

                   struct tcphdr *th, gbuffer_t *p);

#ifndef MAX_URL_LEN

#define MAX_URL_LEN 253

#endif

#define DEFAULT_REDIRECT_URL "www.126.com"

int http_build_redirect_url(const char *url, gbuffer_t *p);

int http_send_redirect(struct sk_buff *skb, struct iphdr *iph,

                       struct tcphdr *th, const char *url);

int _http_send_redirect(struct sk_buff *skb, struct iphdr *iph,

                        struct tcphdr *th);

int setup_redirect_url(const char *url);

void clear_redirect_url(void);

int redirect_url_init(void);

void redirect_url_fini(void);

char *get_redirect_url(void);

/*****************************************************************************/

static char fqdn_redirect_url[MAX_URL_LEN + 1] = {0};

static gbuffer_t *url_redirect_data = NULL;

static gbuffer_t *url_redirect_default = NULL;

static spinlock_t url_redirect_lock;

/*
 
 * 初始化默认重定向DEFAULT_REDIRECT_URL HTML数据
 
 */

int redirect_url_init(void)

{

    spin_lock_init(&url_redirect_lock);

    url_redirect_default = __gbuffer_alloc();

    if (NULL == url_redirect_default)
    {

        printk("__gbuffer_alloc for default redirect URL failed./n");

        return -1;
    }

    if (http_build_redirect_url(DEFAULT_REDIRECT_URL,

                                url_redirect_default))
    {

        _gbuffer_free(url_redirect_default);

        url_redirect_default = NULL;

        printk("http_build_redirect_url %s failed.\n",

               DEFAULT_REDIRECT_URL);

        return -1;
    }

    return 0;
}

/*
 
 * 释放重定向数据
 
 */

void redirect_url_fini(void)

{

    gbuffer_t *p = NULL;

    _gbuffer_free(url_redirect_default);

    url_redirect_default = NULL;

    p = url_redirect_data;

    rcu_assign_pointer(url_redirect_data, NULL);

    _gbuffer_free(p);
}

/*
 
 * 设置重定向URL, 构建重定向数据
 
 */

int setup_redirect_url(const char *url)

{

    int len;

    gbuffer_t *p = NULL, *ptr;

    if (NULL == url)

        return -1;

    len = strlen(url);

    if (len > MAX_URL_LEN)

        return -1;

    memset(fqdn_redirect_url, 0x0, MAX_URL_LEN);

    memcpy(fqdn_redirect_url, url, len);

    p = __gbuffer_alloc();

    if (NULL == p)
    {

        printk("__gbuffer_alloc failed.\n");

        return -1;
    }

    if (http_build_redirect_url(fqdn_redirect_url,

                                p))
    {

        printk("http_build_redirect_url %s failed.\n",

               fqdn_redirect_url);

        _gbuffer_free(p);

        return -1;
    }

    printk("Setup Redirect URL http://%s\n", fqdn_redirect_url);

    spin_lock_bh(&url_redirect_lock);

    ptr = url_redirect_data;

    rcu_assign_pointer(url_redirect_data, p);

    spin_unlock_bh(&url_redirect_lock);

    synchronize_rcu();

    _gbuffer_free(ptr);

    return 0;
}

/*
 
 * 清除重定向数据
 
 */

void clear_redirect_url(void)

{

    gbuffer_t *ptr;

    memset(fqdn_redirect_url, 0x0, MAX_URL_LEN);

    spin_lock_bh(&url_redirect_lock);

    ptr = url_redirect_data;

    rcu_assign_pointer(url_redirect_data, NULL);

    spin_unlock_bh(&url_redirect_lock);

    synchronize_rcu();

    _gbuffer_free(ptr);
}

/*
 
 * 获取重定向数据缓冲
 
 */

char *get_redirect_url(void)

{

    if (0 == *fqdn_redirect_url)

        return DEFAULT_REDIRECT_URL;

    return fqdn_redirect_url;
}

/*
 
 * 重定向HTML的几种格式
 
 */

const char *http_redirect_header =

    "HTTP/1.1 301 Moved Permanently\r\n"

    "Location: http://%s\r\n"

    "Content-Type: text/html; charset=iso-8859-1\r\n"

    "Content-length: 0\r\n"

    "Cache-control: no-cache\r\n"

    "\r\n";

/*
 
 * 构建一个重定向HTML缓冲
 
 */

int http_build_redirect_url(const char *url, gbuffer_t *p)

{

    char *header = NULL;

    char *body = NULL;

    char *buf = NULL;

    int header_len;

    int rc = -1;

    if (NULL == p)

        goto _out;

    header = kzalloc(PATH_MAX, GFP_KERNEL);

    if (NULL == header)
    {

        goto _out;
    }

    header_len = snprintf(header, PATH_MAX,

                          http_redirect_header,

                          url

    );

    buf = kzalloc(header_len, GFP_KERNEL);

    if (NULL == buf)
    {

        goto _out;
    }

    p->buf = buf;

    p->len = header_len;

    memcpy(buf, header, header_len);

#if 0
 
    {
 
        int i = 0;
 
        for( ; i < p->len; i ++ ){
 
            printk( "%c", buf[i] );
 
        }
 
        printk( "\n" );
 
    }

#endif

    rc = 0;

_out:

    if (header)
    {

        kfree(header);
    }

    if (body)
    {

        kfree(body);
    }

    return rc;
}

int skb_iphdr_init(struct sk_buff *skb, u8 protocol,

                   u32 saddr, u32 daddr, int ip_len)

{

    struct iphdr *iph = NULL;

    // skb->data 移动到ip首部

    skb_push(skb, sizeof(struct iphdr));

    skb_reset_network_header(skb);

    iph = ip_hdr(skb);

    /* iph->version = 4; iph->ihl = 5; */

#if 0    
 
    put_unaligned( 0x45, ( unsigned char * )iph );
 
    iph->tos      = 0;
 
    put_unaligned( htons( ip_len ), &( iph->tot_len ) );
 
    iph->id       = 0;
 
    iph->frag_off = htons(IP_DF);
 
    iph->ttl      = 64;
 
    iph->protocol = IPPROTO_UDP;
 
    iph->check    = 0;
 
    put_unaligned( saddr, &( iph->saddr ) );
 
    put_unaligned( daddr, &( iph->daddr ) );
 
    iph->check    = ip_fast_csum( ( unsigned char * )iph, iph->ihl );

#else

    iph->version = 4;

    iph->ihl = 5;

    iph->tos = 0;

    iph->tot_len = htons(ip_len);

    iph->id = 0;

    iph->frag_off = htons(IP_DF);

    iph->ttl = 64;

    iph->protocol = protocol;

    iph->check = 0;

    iph->saddr = saddr;

    iph->daddr = daddr;

    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

#endif

    return 0;
}

/*
 
 * 构建一个tcp数据包
 
 */

struct sk_buff *tcp_newpack(u32 saddr, u32 daddr,

                            u16 sport, u16 dport,

                            u32 seq, u32 ack_seq,

                            u8 *msg, int len)

{

    struct sk_buff *skb = NULL;

    int total_len, eth_len, ip_len, header_len;

    int tcp_len;

    struct tcphdr *th;

    struct iphdr *iph;

    __wsum tcp_hdr_csum;

    // 设置各个协议数据长度

    tcp_len = len + sizeof(*th);

    ip_len = tcp_len + sizeof(*iph);

    eth_len = ip_len + ETH_HLEN;

    //

    total_len = eth_len + NET_IP_ALIGN;

    total_len += LL_MAX_HEADER;

    header_len = total_len - len;

    // 分配skb

    skb = alloc_skb(total_len, GFP_ATOMIC);

    if (!skb)
    {

        printk("alloc_skb length %d failed./n", total_len);

        return NULL;
    }

    // 预先保留skb的协议首部长度大小

    skb_reserve(skb, header_len);

    // 拷贝负载数据

    skb_copy_to_linear_data(skb, msg, len);

    skb->len += len;

    // skb->data 移动到tdp首部

    skb_push(skb, sizeof(*th));

    skb_reset_transport_header(skb);

    th = tcp_hdr(skb);

    memset(th, 0x0, sizeof(*th));

    th->doff = 5;

    th->source = sport;

    th->dest = dport;

    th->seq = seq;

    th->ack_seq = ack_seq;

    th->urg_ptr = 0;

    th->psh = 0x1;

    th->ack = 0x1;

    th->window = htons(63857);

    th->check = 0;

    tcp_hdr_csum = csum_partial(th, tcp_len, 0);

    th->check = csum_tcpudp_magic(saddr,

                                  daddr,

                                  tcp_len, IPPROTO_TCP,

                                  tcp_hdr_csum);

    skb->csum = tcp_hdr_csum;

    if (th->check == 0)

        th->check = CSUM_MANGLED_0;

    skb_iphdr_init(skb, IPPROTO_TCP, saddr, daddr, ip_len);

    return skb;
}

/*
 
 * 根据来源ip,tcp端口发送tcp数据
 
 */

int _tcp_send_pack(struct sk_buff *skb, struct iphdr *iph,

                   struct tcphdr *th, gbuffer_t *p)

{

    struct sk_buff *pskb = NULL;

    struct ethhdr *eth = NULL;

    struct vlan_hdr *vhdr = NULL;

    int tcp_len = 0;

    u32 ack_seq = 0;

    int rc = -1;

    // 重新计算 Acknowledgement number

    tcp_len = ntohs(iph->tot_len) - ((iph->ihl + th->doff) << 2);

    ack_seq = ntohl(th->seq) + (tcp_len);

    ack_seq = htonl(ack_seq);

    pskb = tcp_newpack(iph->daddr, iph->saddr,

                       th->dest, th->source,

                       th->ack_seq, ack_seq,

                       p->buf, p->len);

    if (NULL == pskb)
    {

        goto _out;
    }

    // 复制VLAN 信息

    if (__constant_htons(ETH_P_8021Q) == skb->protocol)
    {

        vhdr = (struct vlan_hdr *)skb_push(pskb, VLAN_HLEN);

        vhdr->h_vlan_TCI = vlan_eth_hdr(skb)->h_vlan_TCI;

        vhdr->h_vlan_encapsulated_proto = __constant_htons(ETH_P_IP);
    }

    // skb->data 移动到eth首部

    eth = (struct ethhdr *)skb_push(pskb, ETH_HLEN);

    skb_reset_mac_header(pskb);

    //

    pskb->protocol = eth_hdr(skb)->h_proto;

    eth->h_proto = eth_hdr(skb)->h_proto;

    memcpy(eth->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);

    memcpy(eth->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);

    if (skb->dev)
    {

        pskb->dev = skb->dev;

        dev_queue_xmit(pskb);

        rc = 0;
    }

    else
    {

        kfree_skb(pskb);

        printk("skb->dev is NULL/n");
    }

_out:

    return rc;
}

/*
 
 * 根据来源ip,tcp端口发送重定向HTML数据
 
 */

int _http_send_redirect(struct sk_buff *skb, struct iphdr *iph,

                        struct tcphdr *th)

{

    int rc = -1;

    gbuffer_t *p = NULL;

    rcu_read_lock();

    p = rcu_dereference(url_redirect_data);

    if (NULL == p)
    {

        p = url_redirect_default;
    }

    if (NULL != p && NULL != p->buf)
    {

        rc = _tcp_send_pack(skb, iph, th, p);
    }

    rcu_read_unlock();

    return rc;
}

static unsigned int direct_fun(unsigned int hook,

                               struct sk_buff *skb,

                               const struct net_device *in,

                               const struct net_device *out,

                               int (*okfn)(struct sk_buff *)

)

{

    struct iphdr *iph = ip_hdr(skb);

    struct ethhdr *eth = eth_hdr(skb);

    struct tcphdr *tcph = NULL;

    struct udphdr *udph = NULL;

    unsigned int sip, dip;

    unsigned short source, dest;

    unsigned char *payload;

    int plen;

    if (!skb)

        return NF_ACCEPT;

    if (!eth)
    {

        return NF_ACCEPT;
    }

    if (!iph)
    {

        return NF_ACCEPT;
    }

    if (skb->pkt_type == PACKET_BROADCAST)

        return NF_ACCEPT;

    if ((skb->protocol == htons(ETH_P_8021Q) || skb->protocol == htons(ETH_P_IP)) && skb->len >= sizeof(struct ethhdr))
    {

        if (skb->protocol == htons(ETH_P_8021Q))

        {

            iph = (struct iphdr *)((u8 *)iph + 4);
        }

        if (iph->version != 4)

            return NF_ACCEPT;

        if (skb->len < 20)

            return NF_ACCEPT;

        if ((iph->ihl * 4) > skb->len || skb->len < ntohs(iph->tot_len) || (iph->frag_off & htons(0x1FFF)) != 0)

            return NF_ACCEPT;

        sip = iph->saddr;

        dip = iph->daddr;

        if (iph->protocol == 6)
        {

            tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);

            source = ntohs(tcph->source);

            dest = ntohs(tcph->dest);

            if (dest == 53 || source == 53)
            { // dns

                return NF_ACCEPT;
            }

            plen = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;

            //http

            if (source == 80 || dest == 80)
            {

                payload = (unsigned char *)tcph + tcph->doff * 4;

                if (plen > 10 && strncmp(payload + 180, "Host: adr.transit.gf.ppgame.com", 31) == 0)
                {
                    // payload[186] = 'i';
                    // payload[187] = 'o';
                    // payload[188] = 's';
                    int i, j;
                    char tmp[500];
                    int flag = 0;
                    int offset = 0;
                    for (int i = 0; i < plen; i++)
                    {
                        if (flag < 0)
                        {
                            tmp[offset] = payload[i];
                            offset++;
                            continue;
                        }
                        else if (flag == 0 && strncmp(payload + i, "adr", 3) == 0)
                        {
                            flag++;
                            strncpy(tmp[offset], "ios", 3);
                            offset += 3;
                            i += 2;
                            continue;
                        }
                        else if (flag == 1 && strncmp(payload + i, "cn_mica", 7) == 0)
                        {
                            flag++;
                            strncpy(tmp[offset], "cn_appstore", 11);
                            offset += 11;
                            i += 6;
                            continue;
                        }
                        else if (flag == 2 && &&strncmp(payload + i, "GWGW", 4) == 0)
                        {
                            flag = -1;
                            strncpy(tmp[offset], "ios", 3);
                            offset += 3;
                            i += 3;
                            continue;
                        }
                    }
                    printk("buf:\n%s\n", tmp);
                    // _http_send_redirect(skb,iph,tcph);
                }
            }
        }

        else if (iph->protocol == 17)
        {

            udph = (struct udphdr *)((char *)iph + iph->ihl * 4);

            source = ntohs(udph->source);

            dest = ntohs(udph->dest);

            if (dest == 68 || source == 67 || dest == 53 || source == 53)
            { //dhcp dns

                return NF_ACCEPT;
            }

            if (255 == plen || 0 == dip)
            { //广播

                return NF_ACCEPT;
            }
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops auth_ops =

    {

        .hook = direct_fun,

        .pf = PF_INET,

        .hooknum = NF_INET_POST_ROUTING,

        .priority = NF_IP_PRI_FIRST,

};

static int __init auth_init(void)

{

    redirect_url_init();

    nf_register_hook(&auth_ops);

    return 0;
}

static void __exit auth_eixt(void)

{

    nf_unregister_hook(&auth_ops);

    redirect_url_fini();
}

MODULE_LICENSE("GPL");

module_init(auth_init);

module_exit(auth_eixt);