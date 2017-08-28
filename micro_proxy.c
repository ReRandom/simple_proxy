#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/ip.h>
#include <linux/byteorder/generic.h>
#include <linux/hashtable.h>
#include <linux/stringhash.h>
#include <linux/ctype.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/inet.h>

#define MY_MODULE_NAME "micro_proxy"

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Roman Ponomarenko <r.e.p@yandex.ru>");

struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t nr; //число запросов
	uint16_t nq; //число ответов
	uint16_t aq; //число авторитетных ответов
	uint16_t oq; //число дополнительных ответов
};

struct dns_req {
	char *name;
	uint16_t type;
};

struct dns_res {
	uint32_t ttl;
	uint16_t len;
	char *data;
};

struct dns_hash_list {
	struct hlist_node ptr;
	struct dns_res res;
	char *name;
	uint16_t type;
	unsigned long hash;
};

static struct nf_hook_ops hook;
static DECLARE_HASHTABLE(hashtable, 5);

static char *parse_string(char *raw_str, char *dns_header)
{
	size_t i;
	char *buf;

	i = 0;
	buf = NULL;
	while (raw_str[i] != 0) {
		uint8_t size;

		size = raw_str[i++];
		if (size > 63) {
			uint16_t off = ntohs((*(uint16_t *)(&raw_str[i-1]))) &
					(0x3fff);

			raw_str = dns_header + off;
			i = 0;
			continue;
		}
		buf = (char *) krealloc(buf, i+size+1, GFP_KERNEL);
		if (buf == NULL) {
			pr_err("[%s] %s: krealloc returned NULL\n",
					MY_MODULE_NAME, __func__);
		}
		while (size > 0) {
			buf[i-1] = raw_str[i];
			++i;
			--size;
		}
		buf[i-1] = '.';
		buf[i] = 0;
	}
	return buf;
}

size_t get_dns_response_len(struct dns_hash_list *obj)
{
	return sizeof(struct dnshdr) + 2 * (strlen(obj->name) + 1 +
			sizeof(obj->type) + sizeof(uint16_t)) +
			sizeof(obj->res.ttl) +
			sizeof(obj->res.len) + ntohs(obj->res.len);
}

void form_new_ethhdr(struct ethhdr *old_eth, struct ethhdr *new_eth)
{
	unsigned int i;

	memset(new_eth, 0, sizeof(*new_eth));
	i = 0;
	while (i < 6) {
		new_eth->h_dest[i] = old_eth->h_source[i];
		new_eth->h_source[i] = old_eth->h_dest[i];
		++i;
	}
	new_eth->h_proto = htons(ETH_P_IP);

}

void form_new_iphdr(struct iphdr *old_ip, struct iphdr *new_ip, size_t len)
{
	memset(new_ip, 0, sizeof(*new_ip));
	new_ip->ihl = 5;
	new_ip->version = IPVERSION;
	new_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
			len);
	new_ip->ttl = IPDEFTTL;
	new_ip->protocol = IPPROTO_UDP;
	new_ip->saddr = old_ip->daddr;
	new_ip->daddr = old_ip->saddr;
	new_ip->check = ip_fast_csum((const void *)new_ip, new_ip->ihl);
}

// (!!!) without checksum (!!!)
void form_new_udphdr(struct udphdr *old_udp, struct udphdr *new_udp, size_t len)
{
	memset(new_udp, 0, sizeof(*new_udp));
	new_udp->source = old_udp->dest;
	new_udp->dest = old_udp->source;
	new_udp->len = htons(sizeof(*new_udp) + len);
}

void form_new_dnshdr(struct dnshdr *new_dns, uint16_t type)
{
	memset(new_dns, 0, sizeof(*new_dns));
	new_dns->id = type;
	new_dns->flags = htons(0x8000);
	new_dns->nr = htons(1);
	new_dns->nq = htons(1);
}

void form_new_dns_response(uint8_t *response, uint8_t *skb_dns,
		struct dnshdr *dnshdr, struct dns_hash_list *obj)
{
	size_t len;

	memcpy(response, dnshdr, sizeof(*dnshdr));
	response += sizeof(*dnshdr);
	skb_dns += sizeof(*dnshdr);
	len = strlen(obj->name) + 1 + 2*sizeof(uint16_t);
	memcpy(response, skb_dns, len);
	response += len;
	memcpy(response, skb_dns, len);
	response += len;
	memcpy(response, &obj->res, sizeof(obj->res.ttl) +
			sizeof(obj->res.len));
	response += sizeof(obj->res.ttl) + sizeof(obj->res.len);
	memcpy(response, obj->res.data, ntohs(obj->res.len));
}

void response(struct sk_buff *skb, struct dns_hash_list *obj)
{
	struct iphdr *old_ip = ip_hdr(skb);
	struct udphdr *old_udp = udp_hdr(skb);
	struct ethhdr *old_eth = (struct ethhdr *)
		((uint8_t *)old_ip - ETH_HLEN);
	struct sk_buff *nskb;
	struct iphdr ip;
	struct udphdr udp;
	struct ethhdr eth;
	struct dnshdr dns;
	uint8_t *dns_response;

	form_new_ethhdr(old_eth, &eth);
	form_new_iphdr(old_ip, &ip, get_dns_response_len(obj));
	form_new_udphdr(old_udp, &udp, get_dns_response_len(obj));
	form_new_dnshdr(&dns, *(uint16_t *)(skb_transport_header(skb) +
				sizeof(struct udphdr)));

	dns_response = (uint8_t *)kmalloc(get_dns_response_len(obj),
							GFP_KERNEL);
	form_new_dns_response(dns_response,
			(uint8_t *)(skb_transport_header(skb) +
				sizeof(struct udphdr)),
			&dns, obj);
	nskb = alloc_skb(sizeof(eth) + sizeof(ip) + sizeof(udp) +
			get_dns_response_len(obj), GFP_KERNEL);
	skb_reserve(nskb, sizeof(eth) + sizeof(ip) + sizeof(udp));

	nskb->mac_header = 0;
	nskb->network_header = (__u16)sizeof(eth);
	nskb->transport_header = (__u16)(nskb->network_header + sizeof(ip));

	skb_put(nskb, get_dns_response_len(obj));
	memcpy(nskb->data, dns_response, get_dns_response_len(obj));

	skb_push(nskb, sizeof(udp));
	memcpy(nskb->data, &udp, sizeof(udp));

	skb_push(nskb, sizeof(ip));
	memcpy(nskb->data, &ip, sizeof(ip));

	skb_push(nskb, sizeof(eth));
	memcpy(nskb->data, &eth, sizeof(eth));

	nskb->dev = skb->dev;
	//ip_local_out(&init_net, NULL, nskb);
	dev_queue_xmit(nskb);
}

unsigned int hook_func(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct dnshdr *dnsh;
	char *str;
	struct dns_hash_list *new_item;
	uint16_t type;
	char *name;
	unsigned long hash;
	struct dns_hash_list *obj;

	if (ntohs(skb->protocol) != ETH_P_IP)
		return NF_ACCEPT;

	ip = ip_hdr(skb);
	if (ip->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	udp = udp_hdr(skb);
	if (ntohs(udp->dest) != 53 && ntohs(udp->source) != 53)
		return NF_ACCEPT;

	dnsh = (struct dnshdr *)((uint8_t *)udp + sizeof(*udp));
	str = (char *)((uint8_t *)dnsh + sizeof(*dnsh));
	//Если это ответ
	if (ntohs(udp->source) == 53) {
		//а флаги говорят запрос (?) что-то пошло не так...
		if ((ntohs(dnsh->flags) & 0x8000) == 0) {
			pr_info("[%s] I get query from server\n",
					MY_MODULE_NAME);
			return NF_ACCEPT;
		}
		//если ответ с ошибкой
		if (ntohs(dnsh->flags) & 0xf) {
			pr_err("[%s] response with error: %hu\n",
					MY_MODULE_NAME,
					ntohs(dnsh->flags) & 0xf);
			return NF_DROP;
		}
		pr_info("[%s] I found correct request\n", MY_MODULE_NAME);
		new_item = (struct dns_hash_list *)
			kmalloc(sizeof(struct dns_hash_list), GFP_KERNEL);
		while (*str != 0)
			++str;
		str += 1 + 2*sizeof(uint16_t);
		new_item->name = parse_string(str, (char *)dnsh);
		if (new_item->name == NULL)
			return NF_DROP;
		while (*str != 0) {
			if (*(uint8_t *)str > 63) {
				str += 2;
				break;
			}
			str += *str + 1;
		}
		new_item->type = *(uint16_t *)(str);
		str += 2*sizeof(uint16_t);
		new_item->res.ttl = *(uint32_t *)(str);
		str += sizeof(uint32_t);
		new_item->res.len = *(uint16_t *)(str);
		str += sizeof(uint16_t);
		new_item->res.data = (void *)kmalloc(ntohs(new_item->res.len),
				GFP_KERNEL);
		memcpy(new_item->res.data, str, ntohs(new_item->res.len));

		new_item->hash = 0;
		str  = new_item->name;
		while (*str)
			new_item->hash += partial_name_hash(tolower(*str++),
					new_item->hash);
		new_item->hash = end_name_hash(new_item->hash);

		pr_info("[%s] get new response for name: %s hash: %lu\n",
				MY_MODULE_NAME, new_item->name, new_item->hash);

		hash_add(hashtable, &new_item->ptr, new_item->hash);
		//TODO: проверка на переполнение
		return NF_ACCEPT;
	} else {
		if (ntohs(dnsh->flags) & 0x8000) {
			pr_info("[%s] dns request\n", MY_MODULE_NAME);
			return NF_DROP;
		}
		type = *(uint16_t *)(str + strlen(str) + 1);

		name = parse_string(str, (char *)udp + sizeof(*udp));
		if (name == NULL)
			return NF_DROP;

		hash = 0;
		str = name;
		while (*str)
			hash += partial_name_hash(tolower(*str++), hash);
		hash = end_name_hash(hash);

		hash_for_each_possible(hashtable, obj, ptr, hash) {
			if (obj->type == type && strcmp(obj->name, name) == 0) {
				pr_info("[%s] send response for name: %s\n",
						MY_MODULE_NAME, name);
				response(skb, obj);
				kfree(name);
				return NF_DROP;
			}
			pr_info("[%s] type: %hx %hx str: %s %s\n",
					MY_MODULE_NAME, obj->type, type,
					obj->name, name);
		}
		kfree(name);
		//TODO: не пропускать дублирующие запросы
		return NF_ACCEPT;

	}
}

static int __init tc_init(void)
{
	pr_info("[%s] init\n", MY_MODULE_NAME);
	hook.hook = hook_func;
	hook.pf = PF_INET;
	hook.hooknum = NF_INET_PRE_ROUTING;
	hook.priority = NF_IP_PRI_FIRST;
	if (nf_register_hook(&hook) != 0)
		pr_err("[%s] error nf_register_hook\n", MY_MODULE_NAME);
	hash_init(hashtable);
	return 0;
}

static void __exit tc_exit(void)
{
	int b;
	struct dns_hash_list *obj;

	pr_info("[%s] exit \n", MY_MODULE_NAME);
	nf_unregister_hook(&hook);
	hash_for_each(hashtable, b, obj, ptr)
		hash_del(&obj->ptr);
}

module_init(tc_init);
module_exit(tc_exit);
