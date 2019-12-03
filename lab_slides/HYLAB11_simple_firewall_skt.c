#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
/*필요에 따라 linux/skbuff.h 또는 linux/icmp.h, linux/udp.h와 같은 header를 필요로 할 수 있음*/

static struct nf_hook_ops nfho; // 함수 선언을 위한 netfilter hook 구조체 선언

//print dropping address
//hint 2 참고
void print_addr(struct iphdr *iph)
{
	printk(KERN_INFO "DROPPING PACKET FROM %d.%d.%d.%d to %d.%d.%d.%d\n",
		iph->saddr & 0x000000ff,
		(iph->saddr & 0x0000ff00) >> 8,
		(iph->saddr & 0x00ff0000) >> 16,
		(iph->saddr & 0xff000000) >> 24,
		iph->daddr & 0x000000ff,
		(iph->daddr & 0x0000ff00) >> 8,
		(iph->daddr & 0x00ff0000) >> 16,
		(iph->daddr & 0xff000000) >> 24);
}

//hook 함수
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph; // ip header
	struct tcphdr *tcph; // tcp header
	iph = ip_hdr(skb); // hook에 의해 가로챈 packet을 ip header 구조에 맞춰 ip header 구조체에 넣음
	tcph = (void *)iph + iph->ihl *4; //가로챈 packet을 tcp header 구조에 맞춰 tcp header 구조체에 넣음

	//filtering
	//hint 1,3 참조
	//Socket Programing 관련 상수 : IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP 등
	if(iph->protocol == ... && tcph->dest == ... &&
	 iph->saddr == ... && iph->daddr == ...)
	{
		print_addr(iph);
		return NF_DROP; //Packet을 DROP
	}
	else
		return NF_ACCEPT; //Packet을 수락
}

//netfilter를 적용
int setFilter(void)
{
	printk(KERN_INFO "Filter Registered\n");
	nfho.hook = hook_func; // Packet filtering을 적용할 함수
	nfho.hooknum = ...; // Hook Point 설정
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; // 해당 Hook 함수를 우선시한다는 뜻
	nf_register_net_hook(&init_net, &nfho); //모듈 적용

	return 0;
}

//적용된 netfilter를 해제
void removeFilter(void)
{
	printk(KERN_INFO "Filter is being removed\n");
	nf_unregister_net_hook(&init_net, &nfho); // 모듈 해제
}

module_init(setFilter);
module_exit(removeFilter);
