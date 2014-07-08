/*	$OpenBSD$	*/

/*
 * Copyright (c) 2006 - 2014 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006, 2007 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _UPDATECONF_H
#define _UPDATECONF_H

#include <sys/tree.h>

#include <sys/param.h>		/* MAXHOSTNAMELEN */
#include <limits.h>
#include <imsg.h>

#define CONF_FILE		"/etc/relayd.conf"
#define CHECK_TIMEOUT		200
#define CHECK_INTERVAL		10
#define EMPTY_TABLE		UINT_MAX
#define EMPTY_ID		UINT_MAX
#define TABLE_NAME_SIZE		64
#define	TAG_NAME_SIZE		64
#define	RT_LABEL_SIZE		32
#define SRV_NAME_SIZE		64
#define MAX_NAME_SIZE		64
#define SRV_MAX_VIRTS		16

#define RELAY_MAX_SESSIONS	1024
#define RELAY_TIMEOUT		600
#define RELAY_CACHESIZE		-1	/* use default size */
#define RELAY_MAXPROC		32
#define RELAY_MAXHOSTS		32
#define RELAY_BACKLOG		10

typedef u_int32_t objid_t;

enum direction {
	RELAY_DIR_REQUEST	= 0,
	RELAY_DIR_RESPONSE	= 1
};

struct portrange {
	in_port_t		 val[2];
	u_int8_t		 op;
};

struct address {
	objid_t			 rdrid;
	struct sockaddr_storage	 ss;
	int			 ipproto;
	struct portrange	 port;
	char			 ifname[IFNAMSIZ];
	TAILQ_ENTRY(address)	 entry;
};
TAILQ_HEAD(addresslist, address);

#define F_DISABLE		0x00000001
#define F_BACKUP		0x00000002
#define F_USED			0x00000004
#define F_STICKY		0x00000008
#define F_SSL			0x00000010
#define F_NATLOOK		0x00000020
#define F_DEMOTE		0x00000040
#define F_UDP			0x00000080
#define F_RETURN		0x00000100
#define F_PORT			0x00000200
#define F_SSLCLIENT		0x00000400
#define F_NEEDRT		0x00000800
#define F_DIVERT		0x00001000

enum forwardmode {
	FWD_NORMAL		= 0,
	FWD_ROUTE,
	FWD_TRANS
};

struct host_config {
	objid_t			 id;
	objid_t			 parentid;
	objid_t			 tableid;
	int			 retry;
	char			 name[MAXHOSTNAMELEN];
	struct sockaddr_storage	 ss;
	int			 ttl;
	int			 priority;
};

struct host {
	TAILQ_ENTRY(host)	 entry;
	SLIST_ENTRY(host)	 child;
	SLIST_HEAD(,host)	 children;
	struct host_config	 conf;
	u_int32_t		 flags;
	char			*tablename;
	int			 up;
	int			 last_up;
	u_long			 check_cnt;
	u_long			 up_cnt;
	int			 retry_cnt;
	int			 idx;
	u_int16_t		 he;
};
TAILQ_HEAD(hostlist, host);

enum digest_type {
	DIGEST_NONE		= 0,
	DIGEST_SHA1		= 1,
	DIGEST_MD5		= 2
};

struct table_config {
	objid_t			 id;
	objid_t			 rdrid;
	u_int32_t		 flags;
	int			 check;
	char			 demote_group[IFNAMSIZ];
	char			 ifname[IFNAMSIZ];
	struct timeval		 timeout;
	in_port_t		 port;
	int			 retcode;
	int			 skip_cnt;
	char			 name[TABLE_NAME_SIZE];
	char			 path[MAXPATHLEN];
	char			 exbuf[64];
	char			 digest[41]; /* length of sha1 digest * 2 */
	u_int8_t		 digest_type;
	enum forwardmode	 fwdmode;
};

struct table {
	TAILQ_ENTRY(table)	 entry;
	struct table_config	 conf;
	struct hostlist		 hosts;
	char			*sendbuf;
};
TAILQ_HEAD(tablelist, table);

enum table_check {
	CHECK_NOCHECK		= 0,
	CHECK_ICMP		= 1,
	CHECK_TCP		= 2,
	CHECK_HTTP_CODE		= 3,
	CHECK_HTTP_DIGEST	= 4,
	CHECK_SEND_EXPECT	= 5,
	CHECK_SCRIPT		= 6
};

struct rdr_config {
	objid_t			 id;
	u_int32_t		 flags;
	in_port_t		 port;
	objid_t			 table_id;
	objid_t			 backup_id;
	int			 mode;
	char			 name[SRV_NAME_SIZE];
	char			 tag[TAG_NAME_SIZE];
	struct timeval		 timeout;
};

struct rdr {
	TAILQ_ENTRY(rdr)	 entry;
	struct rdr_config	 conf;
	struct addresslist	 virts;
	struct table		*table;
	struct table		*backup; /* use this if no host up */
	char			**opts;
	size_t			  optsc;
};
TAILQ_HEAD(rdrlist, rdr);

enum nodeaction {
	NODE_ACTION_NONE	= 0,
	NODE_ACTION_APPEND	= 1,
	NODE_ACTION_CHANGE	= 2,
	NODE_ACTION_REMOVE	= 3,
	NODE_ACTION_EXPECT	= 4,
	NODE_ACTION_FILTER	= 5,
	NODE_ACTION_HASH	= 6,
	NODE_ACTION_LOG		= 7,
	NODE_ACTION_MARK	= 8
};

enum nodetype {
	NODE_TYPE_HEADER	= 0,
	NODE_TYPE_QUERY		= 1,
	NODE_TYPE_COOKIE	= 2,
	NODE_TYPE_PATH		= 3,
	NODE_TYPE_URL		= 4
};

#define PNFLAG_MACRO			0x01
#define PNFLAG_LOG			0x02
#define PNFLAG_DIGEST			0x04
#define PNFLAG_NOLABEL			0x08

struct protonode_config {
	objid_t				 protoid;
	size_t				 keylen;
	size_t				 valuelen;
	size_t				 len;
	size_t                           labelnamelen;
	u_int				 dir;
};

struct protonode {
	struct protonode_config		 conf;
	objid_t				 id;
	enum nodeaction			 action;
	u_int8_t			 flags;
	enum nodetype			 type;
	enum direction 			 dir;
	u_int16_t			 mark;
	u_int16_t			 label;

	char                            *labelname;
	char				*key;
	char				*value;

	SIMPLEQ_ENTRY(protonode)	 entry;
	RB_ENTRY(protonode)		 nodes;
};
RB_HEAD(proto_tree, protonode);

#define PROTONODE_FOREACH(elm, root, field)				\
	for (elm = root; elm != NULL; elm = SIMPLEQ_NEXT(elm, entry))	\

enum prototype {
	RELAY_PROTO_TCP		= 0,
	RELAY_PROTO_HTTP	= 1,
	RELAY_PROTO_DNS		= 2
};

#define TCPFLAG_NODELAY		0x01
#define TCPFLAG_NNODELAY	0x02
#define TCPFLAG_SACK		0x04
#define TCPFLAG_NSACK		0x08
#define TCPFLAG_BUFSIZ		0x10
#define TCPFLAG_IPTTL		0x20
#define TCPFLAG_IPMINTTL	0x40
#define TCPFLAG_NSPLICE		0x80
#define TCPFLAG_DEFAULT		0x00

#define SSLFLAG_SSLV2		0x01
#define SSLFLAG_SSLV3		0x02
#define SSLFLAG_TLSV1		0x04
#define SSLFLAG_VERSION		0x07
#define SSLFLAG_DEFAULT		(SSLFLAG_SSLV3|SSLFLAG_TLSV1)

#define SSLCIPHERS_DEFAULT	"HIGH:!aNULL"
#define SSLECDHCURVE_DEFAULT	NID_X9_62_prime256v1

struct protocol {
	objid_t			 id;
	u_int32_t		 flags;
	u_int8_t		 tcpflags;
	int			 tcpbufsiz;
	int			 tcpbacklog;
	u_int8_t		 tcpipttl;
	u_int8_t		 tcpipminttl;
	u_int8_t		 sslflags;
	char			 sslciphers[768];
	int			 sslecdhcurve;
	char			 sslca[MAXPATHLEN];
	char			 sslcacert[MAXPATHLEN];
	char			 sslcakey[MAXPATHLEN];
	char			*sslcapass;
	char			 name[MAX_NAME_SIZE];
	int			 cache;
	enum prototype		 type;
	char			*style;

	int			 request_nodes;
	int			 response_nodes;
	char			**opts;
	size_t			  optsc;
	char			**rules;
	size_t			  rulesc;

	TAILQ_ENTRY(protocol)	 entry;
};
TAILQ_HEAD(protolist, protocol);

struct relay_table {
	struct table		*rlt_table;
	u_int32_t		 rlt_flags;
	int			 rlt_mode;
	u_int32_t		 rlt_key;
	struct host		*rlt_host[RELAY_MAXHOSTS];
	int			 rlt_nhosts;
	TAILQ_ENTRY(relay_table) rlt_entry;
};
TAILQ_HEAD(relaytables, relay_table);

struct relay_config {
	objid_t			 id;
	u_int32_t		 flags;
	objid_t			 proto;
	char			 name[MAXHOSTNAMELEN];
	char			 ifname[IFNAMSIZ];
	in_port_t		 port;
	in_port_t		 dstport;
	int			 dstretry;
	struct sockaddr_storage	 ss;
	struct sockaddr_storage	 dstss;
	struct sockaddr_storage	 dstaf;
	struct timeval		 timeout;
	enum forwardmode	 fwdmode;
	off_t			 ssl_cert_len;
	off_t			 ssl_key_len;
	objid_t			 ssl_keyid;
	off_t			 ssl_ca_len;
	off_t			 ssl_cacert_len;
	off_t			 ssl_cakey_len;
	objid_t			 ssl_cakeyid;
};

struct relay {
	TAILQ_ENTRY(relay)	 rl_entry;
	struct relay_config	 rl_conf;
	int			 rl_up;
	struct protocol		*rl_proto;
	int			 rl_dsts;
	struct relaytables	 rl_tables;
	char			**rl_opts;
	size_t			  rl_optsc;
};
TAILQ_HEAD(relaylist, relay);

enum dstmode {
	RELAY_DSTMODE_LOADBALANCE = 0,
	RELAY_DSTMODE_ROUNDROBIN,
	RELAY_DSTMODE_HASH,
	RELAY_DSTMODE_SRCHASH,
	RELAY_DSTMODE_LEASTSTATES,
	RELAY_DSTMODE_RANDOM
};
#define RELAY_DSTMODE_DEFAULT		RELAY_DSTMODE_ROUNDROBIN

struct router;
struct netroute_config {
	objid_t			 id;
	struct sockaddr_storage	 ss;
	int			 prefixlen;
	objid_t			 routerid;
};

struct netroute {
	struct netroute_config	 nr_conf;

	TAILQ_ENTRY(netroute)	 nr_entry;
	TAILQ_ENTRY(netroute)	 nr_route;

	struct router		*nr_router;
};
TAILQ_HEAD(netroutelist, netroute);

struct router_config {
	objid_t			 id;
	u_int32_t		 flags;
	char			 name[MAXHOSTNAMELEN];
	char			 label[RT_LABEL_SIZE];
	int			 nroutes;
	objid_t			 gwtable;
	in_port_t		 gwport;
	int			 rtable;
	int			 af;
};

struct router {
	struct router_config	 rt_conf;

	struct table		*rt_gwtable;
	struct netroutelist	 rt_netroutes;
	char			**rt_opts;
	size_t			  rt_optsc;

	TAILQ_ENTRY(router)	 rt_entry;
};
TAILQ_HEAD(routerlist, router);

struct relayd {
	u_int8_t		 sc_opts;
	u_int32_t		 sc_flags;
	const char		*sc_conffile;
	int			 sc_tablecount;
	int			 sc_rdrcount;
	int			 sc_protocount;
	int			 sc_relaycount;
	int			 sc_routercount;
	int			 sc_routecount;
	struct timeval		 sc_interval;
	struct timeval		 sc_timeout;
	struct table		 sc_empty_table;
	struct protocol		 sc_proto_default;
	struct event		 sc_ev;
	struct tablelist	*sc_tables;
	struct rdrlist		*sc_rdrs;
	struct protolist	*sc_protos;
	struct relaylist	*sc_relays;
	struct routerlist	*sc_rts;
	struct netroutelist	*sc_routes;
	struct ca_pkeylist	*sc_pkeys;
	u_int16_t		 sc_prefork_relay;
	u_int16_t		 sc_id;

	const char		*sc_snmp_path;
	int			 sc_snmp_flags;

	char			**sc_mainopts;
	size_t			  sc_mainoptsc;
	char			**sc_tableopts;
	size_t			  sc_tableoptsc;
};

#define RELAYD_OPT_VERBOSE		0x01
#define RELAYD_OPT_NOACTION		0x04
#define RELAYD_OPT_LOGUPDATE		0x08
#define RELAYD_OPT_LOGNOTIFY		0x10
#define RELAYD_OPT_LOGALL		0x18

/* parse.y */
int	 load_config(const char *, struct relayd *);
int	 cmdline_symset(char *);

RB_PROTOTYPE(proto_tree, protonode, se_nodes, relay_proto_cmp);

/* updateconf.c */
int		 config_init(struct relayd *);
__dead void	 fatal(const char *);
const char	*print_host(struct sockaddr_storage *, char *, size_t);
struct host	*host_find(struct relayd *, objid_t);
struct table	*table_findbyname(struct relayd *, const char *);
struct table	*table_findbyconf(struct relayd *, struct table *);
struct relay	*relay_findbyname(struct relayd *, const char *);
struct relay	*relay_findbyaddr(struct relayd *, struct relay_config *);
void		 translate_string(char *);
void		 purge_table(struct tablelist *, struct table *);
struct protonode
		*protonode_header(enum direction, struct protocol *,
		    struct protonode *);
int		 protonode_add(enum direction, struct protocol *,
		    struct protonode *);
int		 protonode_load(enum direction, struct protocol *,
		    struct protonode *, const char *);
char		*print_tcpport(in_port_t);
void		 proto_print_node(struct protocol *, struct protonode *,
		    char **);
void		 proto_print_opts(struct protocol *, char *, size_t);
void		 proto_print_flags(struct protocol *, char *, size_t);
void		 rdr_print_forward(struct rdr *, int, char *, size_t);
void		 rdr_print_listen(struct rdr *, char *, size_t);
void		 relay_print_forward(struct relay *, struct relay_table *,
		     char *, size_t);
void		 relay_print_listen(struct relay *, char *, size_t);
void		 relay_print_session(struct relay *, char *, size_t);
void		 table_print(struct table *, char *, size_t);
char		*getsslflag(u_int8_t);
char		**opts_add(char **, size_t *, const char *);

#endif /* _UPDATECONF_H */
