#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 28 "parse.y"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <sys/hash.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/route.h>

#include <ctype.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <ifaddrs.h>

#include <openssl/ssl.h>

#include "relayd.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...);
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

struct relayd		*conf = NULL;
static int		 errors = 0;
static int		 loadcfg = 0;
objid_t			 last_rdr_id = 0;
objid_t			 last_table_id = 0;
objid_t			 last_host_id = 0;
objid_t			 last_relay_id = 0;
objid_t			 last_proto_id = 0;
objid_t			 last_rt_id = 0;
objid_t			 last_nr_id = 0;

static struct rdr	*rdr = NULL;
static struct table	*table = NULL;
static struct relay	*rlay = NULL;
static struct host	*hst = NULL;
struct relaylist	 relays;
static struct protocol	*proto = NULL;
static struct protonode	 node;
static struct router	*router = NULL;
static u_int16_t	 label = 0;
static in_port_t	 tableport = 0;
static int		 nodedirection;
static int		 dstmode;

struct address	*host_v4(const char *);
struct address	*host_v6(const char *);
int		 host_dns(const char *, struct addresslist *,
		    int, struct portrange *, const char *, int);
int		 host_if(const char *, struct addresslist *,
		    int, struct portrange *, const char *, int);
int		 host(const char *, struct addresslist *,
		    int, struct portrange *, const char *, int);
void		 host_free(struct addresslist *);

struct table	*table_inherit(struct table *);
struct relay	*relay_inherit(struct relay *, struct relay *);
int		 getservice(char *);
int		 is_if_in_group(const char *, const char *);

typedef struct {
	union {
		int64_t			 number;
		char			*string;
		struct host		*host;
		struct timeval		 tv;
		struct table		*table;
		struct portrange	 port;
		struct {
			struct sockaddr_storage	 ss;
			char			 name[MAXHOSTNAMELEN];
		}			 addr;
		struct {
			enum digest_type type;
			char		*digest;
		}			 digest;
	} v;
	int lineno;
} YYSTYPE;

#line 135 "y.tab.c"
#define ALL 257
#define APPEND 258
#define BACKLOG 259
#define BACKUP 260
#define BUFFER 261
#define CA 262
#define CACHE 263
#define CHANGE 264
#define CHECK 265
#define CIPHERS 266
#define CODE 267
#define COOKIE 268
#define DEMOTE 269
#define DIGEST 270
#define DISABLE 271
#define ERROR 272
#define EXPECT 273
#define EXTERNAL 274
#define FILENAME 275
#define FILTER 276
#define FORWARD 277
#define FROM 278
#define HASH 279
#define HEADER 280
#define HOST 281
#define ICMP 282
#define INCLUDE 283
#define INET 284
#define INET6 285
#define INTERFACE 286
#define INTERVAL 287
#define IP 288
#define LABEL 289
#define LISTEN 290
#define LOADBALANCE 291
#define LOG 292
#define LOOKUP 293
#define MARK 294
#define MARKED 295
#define MODE 296
#define NAT 297
#define NO 298
#define DESTINATION 299
#define NODELAY 300
#define NOTHING 301
#define ON 302
#define PARENT 303
#define PATH 304
#define PORT 305
#define PREFORK 306
#define PRIORITY 307
#define PROTO 308
#define QUERYSTR 309
#define REAL 310
#define REDIRECT 311
#define RELAY 312
#define REMOVE 313
#define REQUEST 314
#define RESPONSE 315
#define RETRY 316
#define RETURN 317
#define ROUNDROBIN 318
#define ROUTE 319
#define SACK 320
#define SCRIPT 321
#define SEND 322
#define SESSION 323
#define SOCKET 324
#define SPLICE 325
#define SSL 326
#define STICKYADDR 327
#define STYLE 328
#define TABLE 329
#define TAG 330
#define TCP 331
#define TIMEOUT 332
#define TO 333
#define ROUTER 334
#define RTLABEL 335
#define TRANSPARENT 336
#define TRAP 337
#define UPDATES 338
#define URL 339
#define VIRTUAL 340
#define WITH 341
#define TTL 342
#define RTABLE 343
#define MATCH 344
#define RANDOM 345
#define LEASTSTATES 346
#define SRCHASH 347
#define STRING 348
#define NUMBER 349
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   24,   12,   12,   13,   13,    4,    1,    1,   16,
   16,   16,   15,   15,   15,   32,   32,   35,   35,   33,
   18,   18,   25,   36,   36,   26,   26,   26,   26,   26,
    5,    5,   37,   27,   39,   39,   40,   40,   40,   40,
   40,   40,   40,   17,   17,   10,   10,   10,    3,   43,
   28,   42,   42,   44,   44,   45,   45,   46,   46,   48,
   23,   47,   47,   49,   49,   49,   49,   49,   49,   50,
   50,   50,   50,   50,   50,   50,   22,   52,   30,   51,
   51,   51,   53,   53,   54,   54,   54,   54,   54,   54,
   54,   54,   60,   54,   54,    7,    7,    7,   58,   58,
   57,   57,   57,   57,   57,   57,   57,   57,   57,   56,
   56,   55,   55,   55,   55,   55,    9,   59,   59,   59,
   64,   59,   59,   59,   65,   59,   59,   59,   59,   66,
   59,   59,   59,   59,   67,   59,   59,   59,   63,   62,
   69,   69,   68,   68,    6,   61,   61,   61,   61,   61,
   14,   14,   70,   29,   71,   71,   72,   72,   72,   72,
   72,   72,   73,   73,   73,   73,    8,    8,    8,    8,
    8,    8,    8,   75,   31,   76,   76,   77,   77,   77,
   77,   77,   77,   74,   74,   74,    2,    2,   79,   19,
   78,   78,   80,   80,   81,   81,   81,   81,   20,   11,
   11,   21,   34,   34,   34,   38,   38,   41,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    0,    3,    2,    3,    3,    3,    3,    3,    3,    3,
    3,    2,    0,    1,    0,    2,    1,    0,    2,    0,
    1,    1,    0,    1,    1,    3,    1,    0,    1,    2,
    2,    2,    3,    1,    1,    2,    2,    2,    2,    2,
    1,    1,    0,    7,    3,    2,    4,    6,    1,    1,
    3,    3,    1,    0,    1,    1,    1,    2,    3,    0,
    4,    2,    1,    1,    4,    3,    2,    1,    1,    0,
    3,    2,    1,    2,    1,    2,    2,    2,    2,    1,
    1,    1,    5,    4,    5,    2,    2,    0,    5,    0,
    2,    4,    3,    2,    2,    4,    2,    4,    3,    5,
    2,    2,    0,    3,    1,    0,    1,    1,    3,    1,
    1,    2,    1,    2,    1,    2,    2,    3,    3,    3,
    1,    3,    2,    3,    2,    1,    1,    6,    6,    4,
    0,    4,    6,    4,    0,    4,    4,    6,    4,    0,
    4,    4,    4,    4,    0,    4,    8,    6,    3,    2,
    0,    2,    0,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    0,    7,    3,    2,    5,    6,    3,    2,
    1,    1,    3,    3,    2,    1,    0,    1,    1,    1,
    1,    1,    1,    0,    7,    3,    2,    4,    3,    2,
    2,    1,    1,    0,    1,    2,    0,    2,    0,    3,
    0,    1,    2,    1,    2,    2,    2,    3,    1,    0,
    2,    1,    1,    1,    0,    2,    0,    2,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   21,    0,    0,    0,    3,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   11,   12,   36,   42,   41,   37,
   39,   43,  163,   40,    0,   60,  212,   38,  184,    0,
    0,    2,    4,    5,    6,    7,    8,    9,   10,    0,
    0,    0,    0,    0,   33,   88,    0,    0,   59,   64,
    0,    0,   63,    0,    0,    0,    0,    0,    0,   62,
    0,    0,   89,  216,   49,   56,    0,   57,    0,   50,
    0,   55,    0,    0,   53,    0,    0,  171,    0,    0,
    0,    0,  172,    0,    0,  209,   68,  199,   69,    0,
    0,  192,    0,    0,    0,    0,  193,    0,    0,   91,
    0,    0,    0,   58,    0,    0,   44,    0,   46,    0,
  170,    0,    0,    0,  164,    0,  166,    0,   65,    0,
  213,    0,   67,  214,    0,    0,  191,  190,  185,    0,
  187,    0,    0,  107,  108,    0,    0,    0,  103,  105,
    0,    0,    0,   52,   70,    0,   51,    0,   45,    0,
  169,   16,    0,  165,    0,    0,    0,    0,  200,  202,
    0,    0,   66,  189,    0,  186,  101,  102,    0,    0,
    0,    0,    0,  127,    0,  126,   95,    0,    0,    0,
  113,  111,    0,  115,    0,   97,    0,   92,    0,   94,
   24,   25,    0,    0,    0,   47,  218,    0,    0,    0,
    0,    0,  176,    0,    0,  206,  207,  205,  203,  188,
    0,    0,   29,   99,    0,  123,  125,    0,    0,    0,
  117,    0,  114,  112,  116,    0,    0,    0,  158,  156,
  159,  157,  160,  104,    0,   93,    0,    0,    0,    0,
    0,    0,   75,   71,    0,  198,   31,   32,   14,  167,
    0,    0,  175,    0,    0,  208,   30,    0,    0,  124,
  162,  161,  122,    0,   96,  119,  118,    0,   98,    0,
    0,    0,    0,    0,    0,    0,    0,   48,   80,    0,
    0,   82,   81,   17,    0,   74,   77,   78,  180,  178,
  179,  183,  181,  182,   79,   76,   72,  174,  211,  173,
  195,    0,  168,  100,    0,  120,  109,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   86,   34,   35,    0,    0,  196,   26,    0,
    0,   87,    0,    0,  134,    0,  137,    0,  136,    0,
  139,  142,  141,  143,  144,  146,    0,    0,  130,  132,
    0,    0,    0,    0,    0,    0,  155,  152,  154,  150,
    0,    0,    0,    0,    0,   19,    0,   84,  128,  129,
  133,  149,  138,    0,  148,   85,   83,    0,  147,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                       1,
  363,  206,  155,  295,   30,  368,  149,  305,  186,   83,
  263,  260,  124,  273,  203,   16,   84,  253,   97,   98,
   38,  322,  156,   85,   18,   19,   20,   21,   22,   23,
   24,  268,  269,  132,  224,  336,   50,   67,   86,   87,
  134,   62,   53,   63,  100,  101,  254,  204,  255,  296,
   73,   65,  151,  152,  229,  230,  237,  238,  244,  197,
  245,  345,  349,  332,  323,  326,  329,  370,  346,   51,
   94,   95,  214,  313,   54,  108,  109,  169,  128,  170,
  171,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                      0,
  -10,   31, -297, -294, -244, -288, -265, -257, -222,   36,
    0, -210, -194,   80,    0, -134,  162,  173,  174,  175,
  181,  192,  194,  199,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -138,    0,    0,    0,    0, -133,
 -132,    0,    0,    0,    0,    0,    0,    0,    0,   89,
   94,  157, -113,   97,    0,    0,  211,  211,    0,    0,
  211, -113,    0,  211,  100,  211,  449,  511, -229,    0,
 -213,    2,    0,    0,    0,    0,  -77,    0,  -94,    0,
  -34,    0,  -89,  -74,    0,  -72,  211,    0,  -53,  -91,
  -66,  -70,    0,  450,  211,    0,    0,    0,    0,  144,
   49,    0,  -49,  -68,  -62,  -52,    0,  -85,  211,    0,
 -158,  -61,  -51,    0,   36,  -48,    0,  289,    0,  -45,
    0,  -42,  -20,  -25,    0,  289,    0,  -81,    0,  211,
    0, -229,    0,    0,   36,  263,    0,    0,    0,  289,
    0,  -32,   24,    0,    0,   42, -117,  -35,    0,    0,
  -22,  211, -197,    0,    0,   32,    0,  211,    0,   15,
    0,    0,  -57,    0,  -17,  -21,  -15,   -4,    0,    0,
  -81,    0,    0,    0,   -3,    0,    0,    0, -115,   52,
   -1,    4,   87,    0, -248,    0,    0,   11,    5, -182,
    0,    0,  103,    0,  265,    0, -235,    0,  289,    0,
    0,    0,   15,   98,   13,    0,    0, -302,   40,   77,
   55,   15,    0,   32,   23,    0,    0,    0,    0,    0,
   26,   47,    0,    0,   38,    0,    0, -250,   57,  254,
    0,   39,    0,    0,    0,   43,   57,  262,    0,    0,
    0,    0,    0,    0,  487,    0,   32,  -43,   45,   48,
 -170, -210,    0,    0,   98,    0,    0,    0,    0,    0,
   55,   51,    0,   55, -105,    0,    0,  271,   57,    0,
    0,    0,    0, -248,    0,    0,    0,  265,    0,   50,
   53, -243, -241,   58,   62,   64,   66,    0,    0,   73,
 -269,    0,    0,    0,   74,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   75,    0,    0,   47,    0,    0,   93,   96,   83,
 -142,  137,  160, -108,  137,  160,  137,  137,  160, -261,
  137,  160,    0,    0,    0,  163,  159,    0,    0,   90,
   99,    0,  104,   95,    0,  153,    0,  107,    0,  108,
    0,    0,    0,    0,    0,    0,  110,   95,    0,    0,
  115,  117, -107,  137,  137,  137,    0,    0,    0,    0,
  137,  137,  125,  137,   40,    0,  102,    0,    0,    0,
    0,    0,    0,   95,    0,    0,    0,  153,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                      0,
  140,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  164,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -246,  535,    0,    0,
 -215,  457,    0, -211,  458,  370,  143,    0,    0,    0,
    0,  507,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  143,  -82,    0,    0,    0,
    0,  141,    0,    0,  484,    0,    0,    0,    0,    0,
 -121,    0,    0,    0,    0,    0,    0,    0,  -83,    0,
 -157,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   -9,    0, -118,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -157,  439,  176,    0,    0,  156,    0,  370,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   -8, -116,    0,    0,    0,    0,    0,    0,  219,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  316,    0,
  258,    0,    0,  284,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -120,    0,
    0,    0,    0,    0,    0,    0,  259,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  156,    0,    0,    0,
   46,    0,    0,    0,  134,    0,    0,    0,    0,    0,
  258,    0,    0,  258,  325,    0,    0,    0, -114,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  205,  207,    0,  210,    0,  213,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  145,  145,    0,  145,  145,    0,  145,  145,    0,    0,
  145,    0,    0,    0,    0,    0, -106,    0,    0,    0,
    0,    0,    0,    0,    0,  223,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  145,  145,  145,    0,    0,    0,    0,
  145,  145,    0,  145,   72,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  223,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
    0, -112,  479,    0,    0, -319,    0,    0,  308,  -16,
 -151,  118,    0,    0,    0,    0,    0,  -75,    0,  390,
  244, -268,  -87,   18,    0,    0,    0,    0,    0,    0,
    0,  182,  319, -207,    0,    0,    0,  -38,    0,  415,
 -102,    0,    0,  442,  373,    0,  252,    0,    0,    0,
    0,    0,    0,  358,  363,  237,  365,  236,    0,    0,
    0,  504, -136,    0,    0,    0,    0,  127,    0,    0,
    0,  422,    0,    0,    0,    0,  411,    0,    0,  349,
    0,
};
#define YYTABLESIZE 878
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      15,
  201,  204,   35,  217,  121,  185,  217,  222,  216,   61,
   27,   66,   28,  180,  325,  159,  357,  181,   17,   68,
  271,  274,   69,  164,  217,   71,  320,   74,  320,  278,
  217,  334,  239,  111,  201,  204,  217,  176,  374,  139,
   25,  217,  217,  217,  240,  257,  258,  174,  119,  182,
   26,   92,  117,    3,   27,  177,  127,  102,  130,  217,
   31,  315,  133,  103,  388,  217,  158,  217,  241,    3,
  141,  217,  217,  242,  183,  213,  217,   92,  335,  358,
  217,   13,   32,  217,  209,   93,   99,  195,  107,  217,
   33,  172,  131,   29,  378,   35,  246,  217,  272,  184,
  131,  265,  198,  243,  321,  104,  324,  217,  299,  308,
  106,   93,  310,  200,   34,  201,  204,  233,   96,  207,
  300,  105,  106,  217,    3,  107,  110,  247,  150,  106,
  142,  217,  217,  201,  288,  343,  264,  234,   37,  143,
   40,  215,  235,   73,  180,  215,  106,  301,  181,   99,
  202,  106,  344,   39,  151,  144,  145,   60,  146,  377,
   18,  215,  320,   18,  217,  197,  218,  147,  150,  350,
  177,   42,  148,   41,  302,  303,  304,  215,  311,  312,
  182,  106,   43,   44,   45,  102,  344,  217,  217,  353,
   46,  103,  356,  217,  217,  360,   13,    3,   75,  217,
  217,   47,  215,   48,   76,  183,  165,  217,   49,   52,
    3,   57,  221,  215,   55,   56,   58,   77,   59,   64,
   66,  166,   72,  188,  112,  167,  215,  215,   28,  217,
  184,  218,  153,  104,  168,  217,  217,  113,  289,  210,
  217,  211,  114,  115,  217,    2,   78,  217,  120,  105,
   79,  217,  189,  217,   80,  116,  121,  106,   73,  217,
    3,  217,  190,   81,  191,  122,  142,  210,  129,  151,
  123,   82,    3,  201,  204,  143,    4,  290,  291,   96,
  197,    5,  292,  135,  192,  137,  153,  293,  193,  194,
  212,  144,  145,  197,  146,    6,  138,  154,  158,  157,
    7,    8,  160,  147,  294,  162,  161,  163,  148,  175,
  177,    9,  178,  179,  177,  177,  177,  205,   10,  208,
   11,   12,  177,   13,  215,   13,  225,  216,  177,  177,
  177,  177,  177,  217,  194,  177,   13,   14,  201,  204,
   13,  177,   13,   28,  218,  220,  226,  153,   13,  228,
  177,  184,  232,  177,   13,   13,   13,   13,   13,  231,
  256,   13,  248,  236,  177,  259,  249,   13,  177,  261,
  262,  266,  177,  267,  221,  177,   13,  177,  275,   13,
  177,  177,  210,  110,  250,  270,  279,  276,  177,  177,
   13,  277,  297,  251,   13,  314,  298,  318,   13,  309,
  319,   13,  208,   13,   73,  327,   13,   13,  197,  328,
   73,  330,  151,  331,   13,   13,   73,   73,   73,   73,
  333,  337,  338,   73,  151,  340,  197,  151,  341,  252,
  342,  344,  197,  151,  348,  361,  151,  364,  197,  362,
   13,   73,  151,  367,  369,  197,  365,   20,  151,  194,
  387,  366,   73,  151,  371,  372,   73,  373,  151,  151,
   73,  151,  375,   73,  376,  384,   61,   90,   73,   73,
  151,   22,   54,   15,  197,  151,   73,   73,  197,  135,
   23,  140,  197,  151,  145,  197,   28,  131,   36,  227,
  153,  197,  386,  136,  217,  306,  339,  223,   28,  197,
  118,   28,  153,   70,  173,  153,  307,   28,  199,  187,
  316,  153,  196,  317,  389,  126,   28,  215,  140,  219,
  153,    0,   28,  188,    0,    0,  153,   28,  210,    0,
    0,  153,   28,   28,  210,   28,  153,  153,    0,  153,
  210,  210,  210,  210,   28,    0,  215,  210,  153,   28,
    0,    0,  189,  153,  197,    0,  215,   28,  215,    0,
  197,  153,  190,  217,  191,  210,  197,  197,  197,    0,
    0,    0,    0,  197,  125,    0,  210,    0,  215,    0,
  210,    0,  215,  215,  192,    0,   13,    0,  193,  194,
    0,  197,   13,  210,    0,  194,    0,    0,   13,    0,
    0,  194,  197,    0,    0,   13,  197,  194,  217,    0,
    0,    0,    0,    0,  194,    0,    0,    0,    0,  197,
    0,    0,    0,   13,    0,    0,    0,    0,  217,    0,
    0,  217,  194,    0,   13,  217,    0,  217,   13,    0,
  217,    0,    0,  194,    0,    0,  217,  194,    0,  217,
    0,   13,  217,    0,    0,    0,    0,  217,  217,  217,
  194,    0,    0,    0,    0,    0,    0,  217,    0,  217,
    0,    0,    0,  217,    0,    0,    0,  217,  217,    0,
    0,    0,    0,  217,  217,    0,  217,    0,  217,  217,
    0,    0,  217,  217,  217,  217,  217,  217,    0,  217,
  217,    0,    0,    0,  217,  217,  217,    0,  217,    0,
    0,    0,  217,  217,    0,    0,    0,  217,  217,   75,
   88,  217,    0,    0,    0,   76,   76,  217,    0,    0,
    0,    3,    3,    0,    0,    0,  217,    0,   77,   89,
    0,    0,  217,    0,  280,    0,    0,  217,    0,    0,
  281,    0,  217,  217,  217,  217,    0,   90,    0,  282,
  217,    0,  283,    0,  217,  284,  217,   78,   78,  217,
    0,   79,   91,  217,  217,   80,    0,  217,  285,    0,
  286,   88,    0,    0,   81,   81,  217,   76,    0,  217,
    0,  217,   82,    3,    0,  217,    0,    0,    0,  287,
   89,    0,  217,    0,  217,  217,  217,    0,    0,    0,
  217,  217,    0,    0,    0,  217,    0,  217,   90,  217,
  217,  217,    0,  217,  217,  347,    0,  351,  352,   78,
  354,  355,  217,   91,  359,    0,    0,  217,    0,    0,
    0,    0,  217,    0,    0,  217,   81,    0,    0,    0,
    0,    0,    0,  217,    0,    0,    0,  217,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  379,  380,  381,
  217,    0,    0,    0,  382,  383,    0,  385,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      10,
   10,   10,   60,  125,  125,  123,  125,  123,  125,  123,
  125,   10,  257,  262,  283,  118,  278,  266,    1,   58,
  271,  229,   61,  126,  271,   64,  270,   66,  270,  237,
  277,  301,  268,   72,   44,   44,  283,  140,  358,  125,
   10,  125,  125,  290,  280,  348,  349,  135,   87,  298,
  348,   68,  125,  283,  349,   10,   95,  271,   10,  271,
  349,  269,  101,  277,  384,  277,   10,  283,  304,  283,
  109,  283,  319,  309,  323,  163,  323,   94,  348,  341,
  327,   10,  348,  330,  160,   68,   69,  123,   71,  336,
  348,  130,   44,  338,  363,   60,  199,  344,  349,  348,
   44,  214,  125,  339,  348,  319,  348,  319,  279,  261,
  268,   94,  264,  152,  337,  125,  125,  300,  348,  158,
  291,  335,  280,  335,  283,  108,  125,  203,  111,  343,
  289,  343,  348,  331,  247,  278,  212,  320,  349,  298,
   61,  262,  325,   10,  262,  266,  304,  318,  266,  132,
  348,  309,  295,  348,   10,  314,  315,  271,  317,  267,
  267,  283,  270,  270,  283,   10,  283,  326,  151,  278,
  125,   10,  331,  308,  345,  346,  347,  298,  284,  285,
  298,  339,   10,   10,   10,  271,  295,  271,  271,  326,
   10,  277,  329,  277,  277,  332,  125,  283,  271,  283,
  283,   10,  323,   10,  277,  323,  288,  290,   10,  348,
  283,  123,  328,  328,  348,  348,  123,  290,   62,  123,
   10,  303,  123,  259,  302,  307,  348,  348,   10,  348,
  348,  348,   10,  319,  316,  319,  319,  332,  282,  297,
  323,  299,  277,  333,  327,  256,  319,  330,  302,  335,
  323,  335,  288,  336,  327,  330,  348,  343,  125,  343,
  283,  344,  298,  336,  300,  332,  289,   10,  125,  125,
  341,  344,  283,  283,  283,  298,  287,  321,  322,  348,
  125,  292,  326,  333,  320,  348,  348,  331,  324,  325,
  348,  314,  315,   10,  317,  306,  349,  349,   10,  348,
  311,  312,  348,  326,  348,  326,  349,  333,  331,   47,
  265,  322,  289,  272,  269,  348,  271,  286,  329,  305,
  331,  332,  277,  334,  342,   10,  275,  349,  283,  284,
  285,  286,  287,  349,   10,  290,  265,  348,  348,  348,
  269,  296,  271,  125,  349,  349,  348,  125,  277,  263,
  305,  348,  348,  308,  283,  284,  285,  286,  287,  349,
  348,  290,  265,  261,  319,  326,  269,  296,  323,  293,
  316,  349,  327,  348,  328,  330,  305,  332,  125,  308,
  335,  336,  125,  125,  287,  348,  125,  349,  343,  344,
  319,  349,  348,  296,  323,  125,  349,  348,  327,  349,
  348,  330,  305,  332,  271,  348,  335,  336,  125,  348,
  277,  348,  268,  348,  343,  344,  283,  284,  285,  286,
  348,  348,  348,  290,  280,  333,  271,  283,  333,  332,
  348,  295,  277,  289,  275,  273,  292,  348,  283,  281,
  125,  308,  298,  349,  292,  290,  348,  308,  304,  125,
  349,  348,  319,  309,  348,  348,  323,  348,  314,  315,
  327,  317,  348,  330,  348,  341,   10,   10,  335,  336,
  326,  308,  330,  333,  319,  331,  343,  344,  323,  275,
  305,  275,  327,  339,  275,  330,  268,  275,   10,  182,
  268,  336,  375,  104,  125,  252,  315,  179,  280,  344,
   86,  283,  280,   62,  132,  283,  255,  289,  151,  147,
  274,  289,  148,  278,  388,   94,  298,  259,  108,  171,
  298,   -1,  304,  259,   -1,   -1,  304,  309,  271,   -1,
   -1,  309,  314,  315,  277,  317,  314,  315,   -1,  317,
  283,  284,  285,  286,  326,   -1,  288,  290,  326,  331,
   -1,   -1,  288,  331,  271,   -1,  298,  339,  300,   -1,
  277,  339,  298,  125,  300,  308,  283,  284,  285,   -1,
   -1,   -1,   -1,  290,  125,   -1,  319,   -1,  320,   -1,
  323,   -1,  324,  325,  320,   -1,  271,   -1,  324,  325,
   -1,  308,  277,  336,   -1,  271,   -1,   -1,  283,   -1,
   -1,  277,  319,   -1,   -1,  290,  323,  283,  125,   -1,
   -1,   -1,   -1,   -1,  290,   -1,   -1,   -1,   -1,  336,
   -1,   -1,   -1,  308,   -1,   -1,   -1,   -1,  259,   -1,
   -1,  262,  308,   -1,  319,  266,   -1,  268,  323,   -1,
  271,   -1,   -1,  319,   -1,   -1,  277,  323,   -1,  280,
   -1,  336,  283,   -1,   -1,   -1,   -1,  288,  289,  290,
  336,   -1,   -1,   -1,   -1,   -1,   -1,  298,   -1,  300,
   -1,   -1,   -1,  304,   -1,   -1,   -1,  308,  309,   -1,
   -1,   -1,   -1,  314,  315,   -1,  317,   -1,  319,  320,
   -1,   -1,  323,  324,  325,  326,  327,  328,   -1,  330,
  331,   -1,   -1,   -1,  335,  336,  268,   -1,  339,   -1,
   -1,   -1,  343,  344,   -1,   -1,   -1,  348,  280,  271,
  271,  283,   -1,   -1,   -1,  277,  277,  289,   -1,   -1,
   -1,  283,  283,   -1,   -1,   -1,  298,   -1,  290,  290,
   -1,   -1,  304,   -1,  258,   -1,   -1,  309,   -1,   -1,
  264,   -1,  314,  315,  271,  317,   -1,  308,   -1,  273,
  277,   -1,  276,   -1,  326,  279,  283,  319,  319,  331,
   -1,  323,  323,  290,  268,  327,   -1,  339,  292,   -1,
  294,  271,   -1,   -1,  336,  336,  280,  277,   -1,  283,
   -1,  308,  344,  283,   -1,  289,   -1,   -1,   -1,  313,
  290,   -1,  319,   -1,  298,  271,  323,   -1,   -1,   -1,
  304,  277,   -1,   -1,   -1,  309,   -1,  283,  308,  336,
  314,  315,   -1,  317,  290,  322,   -1,  324,  325,  319,
  327,  328,  326,  323,  331,   -1,   -1,  331,   -1,   -1,
   -1,   -1,  308,   -1,   -1,  339,  336,   -1,   -1,   -1,
   -1,   -1,   -1,  319,   -1,   -1,   -1,  323,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  364,  365,  366,
  336,   -1,   -1,   -1,  371,  372,   -1,  374,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 349
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyname[] =
#else
char *yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,"','",0,0,"'/'",0,0,0,0,0,0,0,0,0,0,0,0,"'<'","'='",
"'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,"ALL","APPEND","BACKLOG","BACKUP","BUFFER","CA","CACHE","CHANGE","CHECK",
"CIPHERS","CODE","COOKIE","DEMOTE","DIGEST","DISABLE","ERROR","EXPECT",
"EXTERNAL","FILENAME","FILTER","FORWARD","FROM","HASH","HEADER","HOST","ICMP",
"INCLUDE","INET","INET6","INTERFACE","INTERVAL","IP","LABEL","LISTEN",
"LOADBALANCE","LOG","LOOKUP","MARK","MARKED","MODE","NAT","NO","DESTINATION",
"NODELAY","NOTHING","ON","PARENT","PATH","PORT","PREFORK","PRIORITY","PROTO",
"QUERYSTR","REAL","REDIRECT","RELAY","REMOVE","REQUEST","RESPONSE","RETRY",
"RETURN","ROUNDROBIN","ROUTE","SACK","SCRIPT","SEND","SESSION","SOCKET",
"SPLICE","SSL","STICKYADDR","STYLE","TABLE","TAG","TCP","TIMEOUT","TO","ROUTER",
"RTLABEL","TRANSPARENT","TRAP","UPDATES","URL","VIRTUAL","WITH","TTL","RTABLE",
"MATCH","RANDOM","LEASTSTATES","SRCHASH","STRING","NUMBER",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyrule[] =
#else
char *yyrule[] =
#endif
	{"$accept : grammar",
"grammar :",
"grammar : grammar include '\\n'",
"grammar : grammar '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar main '\\n'",
"grammar : grammar rdr '\\n'",
"grammar : grammar tabledef '\\n'",
"grammar : grammar relay '\\n'",
"grammar : grammar proto '\\n'",
"grammar : grammar router '\\n'",
"grammar : grammar error '\\n'",
"include : INCLUDE STRING",
"optssl :",
"optssl : SSL",
"optsslclient :",
"optsslclient : WITH SSL",
"http_type : STRING",
"hostname :",
"hostname : HOST STRING",
"relay_proto :",
"relay_proto : TCP",
"relay_proto : STRING",
"redirect_proto :",
"redirect_proto : TCP",
"redirect_proto : STRING",
"eflags_l : eflags comma eflags_l",
"eflags_l : eflags",
"opteflags :",
"opteflags : eflags",
"eflags : STYLE STRING",
"port : PORT STRING",
"port : PORT NUMBER",
"varset : STRING '=' STRING",
"sendbuf : NOTHING",
"sendbuf : STRING",
"main : INTERVAL NUMBER",
"main : LOG loglevel",
"main : TIMEOUT timeout",
"main : PREFORK NUMBER",
"main : SEND TRAP",
"loglevel : UPDATES",
"loglevel : ALL",
"$$1 :",
"rdr : REDIRECT STRING $$1 '{' optnl rdropts_l '}'",
"rdropts_l : rdropts_l rdroptsl nl",
"rdropts_l : rdroptsl optnl",
"rdroptsl : forwardmode TO tablespec interface",
"rdroptsl : LISTEN ON STRING redirect_proto port interface",
"rdroptsl : DISABLE",
"rdroptsl : STICKYADDR",
"rdroptsl : match TAG STRING",
"rdroptsl : SESSION TIMEOUT NUMBER",
"rdroptsl : include",
"match :",
"match : MATCH",
"forwardmode : FORWARD",
"forwardmode : ROUTE",
"forwardmode : TRANSPARENT FORWARD",
"table : '<' STRING '>'",
"$$2 :",
"tabledef : TABLE table $$2 tabledefopts_l",
"tabledefopts_l : tabledefopts_l tabledefopts",
"tabledefopts_l : tabledefopts",
"tabledefopts : DISABLE",
"tabledefopts : '{' optnl tablelist_l '}'",
"tablelist_l : tablelist comma tablelist_l",
"tablelist_l : tablelist optnl",
"tablelist : host",
"tablelist : include",
"$$3 :",
"tablespec : table $$3 tableopts_l",
"tableopts_l : tableopts tableopts_l",
"tableopts_l : tableopts",
"tableopts : CHECK tablecheck",
"tableopts : port",
"tableopts : TIMEOUT timeout",
"tableopts : DEMOTE STRING",
"tableopts : INTERVAL NUMBER",
"tableopts : MODE dstmode",
"tablecheck : ICMP",
"tablecheck : TCP",
"tablecheck : SSL",
"tablecheck : http_type STRING hostname CODE NUMBER",
"tablecheck : http_type STRING hostname digest",
"tablecheck : SEND sendbuf EXPECT STRING optssl",
"tablecheck : SCRIPT STRING",
"digest : DIGEST STRING",
"$$4 :",
"proto : relay_proto PROTO STRING $$4 protopts_n",
"protopts_n :",
"protopts_n : '{' '}'",
"protopts_n : '{' optnl protopts_l '}'",
"protopts_l : protopts_l protoptsl nl",
"protopts_l : protoptsl optnl",
"protoptsl : SSL sslflags",
"protoptsl : SSL '{' sslflags_l '}'",
"protoptsl : TCP tcpflags",
"protoptsl : TCP '{' tcpflags_l '}'",
"protoptsl : RETURN ERROR opteflags",
"protoptsl : RETURN ERROR '{' eflags_l '}'",
"protoptsl : LABEL STRING",
"protoptsl : NO LABEL",
"$$5 :",
"protoptsl : direction $$5 protonode",
"protoptsl : include",
"direction :",
"direction : REQUEST",
"direction : RESPONSE",
"tcpflags_l : tcpflags comma tcpflags_l",
"tcpflags_l : tcpflags",
"tcpflags : SACK",
"tcpflags : NO SACK",
"tcpflags : NODELAY",
"tcpflags : NO NODELAY",
"tcpflags : SPLICE",
"tcpflags : NO SPLICE",
"tcpflags : BACKLOG NUMBER",
"tcpflags : SOCKET BUFFER NUMBER",
"tcpflags : IP STRING NUMBER",
"sslflags_l : sslflags comma sslflags_l",
"sslflags_l : sslflags",
"sslflags : SESSION CACHE sslcache",
"sslflags : CIPHERS STRING",
"sslflags : CA FILENAME STRING",
"sslflags : NO flag",
"sslflags : flag",
"flag : STRING",
"protonode : nodetype APPEND STRING TO STRING nodeopts",
"protonode : nodetype CHANGE STRING TO STRING nodeopts",
"protonode : nodetype REMOVE STRING nodeopts",
"$$6 :",
"protonode : nodetype REMOVE $$6 nodefile",
"protonode : nodetype EXPECT STRING FROM STRING nodeopts",
"protonode : nodetype EXPECT STRING nodeopts",
"$$7 :",
"protonode : nodetype EXPECT $$7 nodefile",
"protonode : nodetype EXPECT digest nodeopts",
"protonode : nodetype FILTER STRING FROM STRING nodeopts",
"protonode : nodetype FILTER STRING nodeopts",
"$$8 :",
"protonode : nodetype FILTER $$8 nodefile",
"protonode : nodetype FILTER digest nodeopts",
"protonode : nodetype HASH STRING nodeopts",
"protonode : nodetype LOG STRING nodeopts",
"$$9 :",
"protonode : nodetype LOG $$9 nodefile",
"protonode : nodetype MARK STRING FROM STRING WITH mark log",
"protonode : nodetype MARK STRING WITH mark nodeopts",
"nodefile : FILENAME STRING nodeopts",
"nodeopts : marked log",
"marked :",
"marked : MARKED mark",
"log :",
"log : LOG",
"mark : NUMBER",
"nodetype : HEADER",
"nodetype : QUERYSTR",
"nodetype : COOKIE",
"nodetype : PATH",
"nodetype : URL",
"sslcache : NUMBER",
"sslcache : DISABLE",
"$$10 :",
"relay : RELAY STRING $$10 '{' optnl relayopts_l '}'",
"relayopts_l : relayopts_l relayoptsl nl",
"relayopts_l : relayoptsl optnl",
"relayoptsl : LISTEN ON STRING port optssl",
"relayoptsl : forwardmode optsslclient TO forwardspec interface dstaf",
"relayoptsl : SESSION TIMEOUT NUMBER",
"relayoptsl : PROTO STRING",
"relayoptsl : DISABLE",
"relayoptsl : include",
"forwardspec : STRING port retry",
"forwardspec : NAT LOOKUP retry",
"forwardspec : DESTINATION retry",
"forwardspec : tablespec",
"dstmode :",
"dstmode : LOADBALANCE",
"dstmode : ROUNDROBIN",
"dstmode : HASH",
"dstmode : LEASTSTATES",
"dstmode : SRCHASH",
"dstmode : RANDOM",
"$$11 :",
"router : ROUTER STRING $$11 '{' optnl routeopts_l '}'",
"routeopts_l : routeopts_l routeoptsl nl",
"routeopts_l : routeoptsl optnl",
"routeoptsl : ROUTE address '/' NUMBER",
"routeoptsl : FORWARD TO tablespec",
"routeoptsl : RTABLE NUMBER",
"routeoptsl : RTLABEL STRING",
"routeoptsl : DISABLE",
"routeoptsl : include",
"dstaf :",
"dstaf : INET",
"dstaf : INET6 STRING",
"interface :",
"interface : INTERFACE STRING",
"$$12 :",
"host : address $$12 opthostflags",
"opthostflags :",
"opthostflags : hostflags_l",
"hostflags_l : hostflags hostflags_l",
"hostflags_l : hostflags",
"hostflags : RETRY NUMBER",
"hostflags : PARENT NUMBER",
"hostflags : PRIORITY NUMBER",
"hostflags : IP TTL NUMBER",
"address : STRING",
"retry :",
"retry : RETRY NUMBER",
"timeout : NUMBER",
"comma : ','",
"comma : nl",
"comma :",
"optnl : '\\n' optnl",
"optnl :",
"nl : '\\n' optnl",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 1753 "parse.y"

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "all",		ALL },
		{ "append",		APPEND },
		{ "backlog",		BACKLOG },
		{ "backup",		BACKUP },
		{ "buffer",		BUFFER },
		{ "ca",			CA },
		{ "cache",		CACHE },
		{ "change",		CHANGE },
		{ "check",		CHECK },
		{ "ciphers",		CIPHERS },
		{ "code",		CODE },
		{ "cookie",		COOKIE },
		{ "demote",		DEMOTE },
		{ "destination",	DESTINATION },
		{ "digest",		DIGEST },
		{ "disable",		DISABLE },
		{ "error",		ERROR },
		{ "expect",		EXPECT },
		{ "external",		EXTERNAL },
		{ "file",		FILENAME },
		{ "filter",		FILTER },
		{ "forward",		FORWARD },
		{ "from",		FROM },
		{ "hash",		HASH },
		{ "header",		HEADER },
		{ "host",		HOST },
		{ "icmp",		ICMP },
		{ "include",		INCLUDE },
		{ "inet",		INET },
		{ "inet6",		INET6 },
		{ "interface",		INTERFACE },
		{ "interval",		INTERVAL },
		{ "ip",			IP },
		{ "label",		LABEL },
		{ "least-states",	LEASTSTATES },
		{ "listen",		LISTEN },
		{ "loadbalance",	LOADBALANCE },
		{ "log",		LOG },
		{ "lookup",		LOOKUP },
		{ "mark",		MARK },
		{ "marked",		MARKED },
		{ "match",		MATCH },
		{ "mode",		MODE },
		{ "nat",		NAT },
		{ "no",			NO },
		{ "nodelay",		NODELAY },
		{ "nothing",		NOTHING },
		{ "on",			ON },
		{ "parent",		PARENT },
		{ "path",		PATH },
		{ "port",		PORT },
		{ "prefork",		PREFORK },
		{ "priority",		PRIORITY },
		{ "protocol",		PROTO },
		{ "query",		QUERYSTR },
		{ "random",		RANDOM },
		{ "real",		REAL },
		{ "redirect",		REDIRECT },
		{ "relay",		RELAY },
		{ "remove",		REMOVE },
		{ "request",		REQUEST },
		{ "response",		RESPONSE },
		{ "retry",		RETRY },
		{ "return",		RETURN },
		{ "roundrobin",		ROUNDROBIN },
		{ "route",		ROUTE },
		{ "router",		ROUTER },
		{ "rtable",		RTABLE },
		{ "rtlabel",		RTLABEL },
		{ "sack",		SACK },
		{ "script",		SCRIPT },
		{ "send",		SEND },
		{ "session",		SESSION },
		{ "socket",		SOCKET },
		{ "source-hash",	SRCHASH },
		{ "splice",		SPLICE },
		{ "ssl",		SSL },
		{ "sticky-address",	STICKYADDR },
		{ "style",		STYLE },
		{ "table",		TABLE },
		{ "tag",		TAG },
		{ "tcp",		TCP },
		{ "timeout",		TIMEOUT },
		{ "to",			TO },
		{ "transparent",	TRANSPARENT },
		{ "trap",		TRAP },
		{ "ttl",		TTL },
		{ "updates",		UPDATES },
		{ "url",		URL },
		{ "virtual",		VIRTUAL },
		{ "with",		WITH }
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = (char)c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '#' && \
	x != ',' && x != '/'))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		log_warnx("%s: group/world readable/writeable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("%s: malloc", __func__);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("%s: malloc", __func__);
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s: %s", __func__, nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(const char *filename, struct relayd *x_conf)
{
	struct sym	*sym, *next;

	conf = x_conf;
	if (config_init(conf) == -1) {
		log_warn("%s: cannot initialize configuration", __func__);
		return (-1);
	}

	errors = 0;

	if ((file = pushfile(filename, 0)) == NULL)
		return (-1);

	topfile = file;
	setservent(1);

	yyparse();
	errors = file->errors;
	popfile();

	endservent();
	endprotoent();

	/* Free macros */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	return (errors ? -1 : 0);
}

int
load_config(const char *filename, struct relayd *x_conf)
{
	struct sym		*sym, *next;
	struct table		*nexttb;
	struct host		*h, *ph;
	struct relay_table	*rlt;

	conf = x_conf;
	conf->sc_flags = 0;

	loadcfg = 1;
	errors = 0;
	last_host_id = last_table_id = last_rdr_id = last_proto_id =
	    last_relay_id = last_rt_id = last_nr_id = 0;

	rdr = NULL;
	table = NULL;
	rlay = NULL;
	proto = NULL;
	router = NULL;

	if ((file = pushfile(filename, 0)) == NULL)
		return (-1);

	topfile = file;
	setservent(1);

	yyparse();
	errors = file->errors;
	popfile();

	endservent();
	endprotoent();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->sc_opts & RELAYD_OPT_VERBOSE) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (TAILQ_EMPTY(conf->sc_rdrs) &&
	    TAILQ_EMPTY(conf->sc_relays) &&
	    TAILQ_EMPTY(conf->sc_rts)) {
		log_warnx("no actions, nothing to do");
		errors++;
	}

	/* Cleanup relay list to inherit */
	while ((rlay = TAILQ_FIRST(&relays)) != NULL) {
		TAILQ_REMOVE(&relays, rlay, rl_entry);
		while ((rlt = TAILQ_FIRST(&rlay->rl_tables))) {
			TAILQ_REMOVE(&rlay->rl_tables, rlt, rlt_entry);
			free(rlt);
		}
		free(rlay);
	}

	if (timercmp(&conf->sc_timeout, &conf->sc_interval, >=)) {
		log_warnx("global timeout exceeds interval");
		errors++;
	}

	/* Verify that every table is used */
	for (table = TAILQ_FIRST(conf->sc_tables); table != NULL;
	     table = nexttb) {
		nexttb = TAILQ_NEXT(table, entry);
		if (table->conf.port == 0) {
			TAILQ_REMOVE(conf->sc_tables, table, entry);
			while ((h = TAILQ_FIRST(&table->hosts)) != NULL) {
				TAILQ_REMOVE(&table->hosts, h, entry);
				free(h);
			}
			if (table->sendbuf != NULL)
				free(table->sendbuf);
			free(table);
			continue;
		}

		TAILQ_FOREACH(h, &table->hosts, entry) {
			if (h->conf.parentid) {
				ph = host_find(conf, h->conf.parentid);

				/* Validate the parent id */
				if (h->conf.id == h->conf.parentid ||
				    ph == NULL || ph->conf.parentid)
					ph = NULL;

				if (ph == NULL) {
					log_warnx("host parent id %d invalid",
					    h->conf.parentid);
					errors++;
				} else
					SLIST_INSERT_HEAD(&ph->children,
					    h, child);
			}
		}

		if (!(table->conf.flags & F_USED)) {
			log_warnx("unused table: %s", table->conf.name);
			errors++;
		}
		if (timercmp(&table->conf.timeout, &conf->sc_interval, >=)) {
			log_warnx("table timeout exceeds interval: %s",
			    table->conf.name);
			errors++;
		}
	}

	/* Verify that every non-default protocol is used */
	TAILQ_FOREACH(proto, conf->sc_protos, entry) {
		if (!(proto->flags & F_USED)) {
			log_warnx("unused protocol: %s", proto->name);
		}
	}

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	(void)strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}

struct address *
host_v4(const char *s)
{
	struct in_addr		 ina;
	struct sockaddr_in	*sain;
	struct address		*h;

	bzero(&ina, sizeof(ina));
	if (inet_pton(AF_INET, s, &ina) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(NULL);
	sain = (struct sockaddr_in *)&h->ss;
	sain->sin_len = sizeof(struct sockaddr_in);
	sain->sin_family = AF_INET;
	sain->sin_addr.s_addr = ina.s_addr;

	return (h);
}

struct address *
host_v6(const char *s)
{
	struct addrinfo		 hints, *res;
	struct sockaddr_in6	*sa_in6;
	struct address		*h = NULL;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, "0", &hints, &res) == 0) {
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(NULL);
		sa_in6 = (struct sockaddr_in6 *)&h->ss;
		sa_in6->sin6_len = sizeof(struct sockaddr_in6);
		sa_in6->sin6_family = AF_INET6;
		memcpy(&sa_in6->sin6_addr,
		    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		    sizeof(sa_in6->sin6_addr));
		sa_in6->sin6_scope_id =
		    ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;

		freeaddrinfo(res);
	}

	return (h);
}

int
host_dns(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct addrinfo		 hints, *res0, *res;
	int			 error, cnt = 0;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct address		*h;

	if ((cnt = host_if(s, al, max, port, ifname, ipproto)) != 0)
		return (cnt);

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /* DUMMY */
	error = getaddrinfo(s, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		return (0);
	if (error) {
		log_warnx("%s: could not parse \"%s\": %s", __func__, s,
		    gai_strerror(error));
		return (-1);
	}

	for (res = res0; res && cnt < max; res = res->ai_next) {
		if (res->ai_family != AF_INET &&
		    res->ai_family != AF_INET6)
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(NULL);

		if (port != NULL)
			bcopy(port, &h->port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname))
				log_warnx("%s: interface name truncated",
				    __func__);
			freeaddrinfo(res0);
			free(h);
			return (-1);
		}
		if (ipproto != -1)
			h->ipproto = ipproto;
		h->ss.ss_family = res->ai_family;

		if (res->ai_family == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    res->ai_addr)->sin_addr.s_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (cnt == max && res) {
		log_warnx("%s: %s resolves to more than %d hosts", __func__,
		    s, max);
	}
	freeaddrinfo(res0);
	return (cnt);
}

int
host_if(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct ifaddrs		*ifap, *p;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct address		*h;
	int			 cnt = 0, af;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	/* First search for IPv4 addresses */
	af = AF_INET;

 nextaf:
	for (p = ifap; p != NULL && cnt < max; p = p->ifa_next) {
		if (p->ifa_addr->sa_family != af ||
		    (strcmp(s, p->ifa_name) != 0 &&
		    !is_if_in_group(p->ifa_name, s)))
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal("calloc");

		if (port != NULL)
			bcopy(port, &h->port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname))
				log_warnx("%s: interface name truncated",
				    __func__);
			freeifaddrs(ifap);
			return (-1);
		}
		if (ipproto != -1)
			h->ipproto = ipproto;
		h->ss.ss_family = af;

		if (af == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    p->ifa_addr)->sin_addr.s_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    p->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
			sin6->sin6_scope_id = ((struct sockaddr_in6 *)
			    p->ifa_addr)->sin6_scope_id;
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (af == AF_INET) {
		/* Next search for IPv6 addresses */
		af = AF_INET6;
		goto nextaf;
	}

	if (cnt > max) {
		log_warnx("%s: %s resolves to more than %d hosts", __func__,
		    s, max);
	}
	freeifaddrs(ifap);
	return (cnt);
}

int
host(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct address *h;

	h = host_v4(s);

	/* IPv6 address? */
	if (h == NULL)
		h = host_v6(s);

	if (h != NULL) {
		if (port != NULL)
			bcopy(port, &h->port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: interface name truncated",
				    __func__);
				free(h);
				return (-1);
			}
		}
		if (ipproto != -1)
			h->ipproto = ipproto;

		TAILQ_INSERT_HEAD(al, h, entry);
		return (1);
	}

	return (host_dns(s, al, max, port, ifname, ipproto));
}

void
host_free(struct addresslist *al)
{
	struct address	 *h;

	while ((h = TAILQ_FIRST(al)) != NULL) {
		TAILQ_REMOVE(al, h, entry);
		free(h);
	}
}

struct table *
table_inherit(struct table *tb)
{
	char		pname[TABLE_NAME_SIZE + 6];
	struct host	*h, *dsth;
	struct table	*dsttb, *oldtb;

	/* Get the table or table template */
	if ((dsttb = table_findbyname(conf, tb->conf.name)) == NULL) {
		yyerror("unknown table %s", tb->conf.name);
		goto fail;
	}
	if (dsttb->conf.port != 0)
		fatal("invalid table");	/* should not happen */

	if (tb->conf.port == 0) {
		yyerror("invalid port");
		goto fail;
	}

	/* Check if a matching table already exists */
	if (snprintf(pname, sizeof(pname), "%s:%u",
	    tb->conf.name, ntohs(tb->conf.port)) >= (int)sizeof(pname)) {
		yyerror("invalid table name");
		goto fail;
	}
	(void)strlcpy(tb->conf.name, pname, sizeof(tb->conf.name));
	if ((oldtb = table_findbyconf(conf, tb)) != NULL) {
		purge_table(NULL, tb);
		return (oldtb);
	}

	/* Create a new table */
	tb->conf.id = ++last_table_id;
	if (last_table_id == INT_MAX) {
		yyerror("too many tables defined");
		goto fail;
	}
	tb->conf.flags |= dsttb->conf.flags;

	/* Inherit global table options */
	if (tb->conf.timeout.tv_sec == 0 && tb->conf.timeout.tv_usec == 0)
		bcopy(&dsttb->conf.timeout, &tb->conf.timeout,
		    sizeof(struct timeval));

	/* Copy the associated hosts */
	TAILQ_INIT(&tb->hosts);
	TAILQ_FOREACH(dsth, &dsttb->hosts, entry) {
		if ((h = (struct host *)
		    calloc(1, sizeof (*h))) == NULL)
			fatal("out of memory");
		bcopy(dsth, h, sizeof(*h));
		h->conf.id = ++last_host_id;
		if (last_host_id == INT_MAX) {
			yyerror("too many hosts defined");
			free(h);
			goto fail;
		}
		h->conf.tableid = tb->conf.id;
		h->tablename = tb->conf.name;
		SLIST_INIT(&h->children);
		TAILQ_INSERT_TAIL(&tb->hosts, h, entry);
	}

	conf->sc_tablecount++;
	TAILQ_INSERT_TAIL(conf->sc_tables, tb, entry);

	return (tb);

 fail:
	purge_table(NULL, tb);
	return (NULL);
}

struct relay *
relay_inherit(struct relay *ra, struct relay *rb)
{
	struct relay_config	 rc;
	struct relay_table	*rta, *rtb;

	bcopy(&rb->rl_conf, &rc, sizeof(rc));
	bcopy(ra, rb, sizeof(*rb));

	bcopy(&rc.ss, &rb->rl_conf.ss, sizeof(rb->rl_conf.ss));
	rb->rl_conf.port = rc.port;
	rb->rl_conf.flags =
	    (ra->rl_conf.flags & ~F_SSL) | (rc.flags & F_SSL);
	TAILQ_INIT(&rb->rl_tables);

	rb->rl_conf.id = ++last_relay_id;
	if (last_relay_id == INT_MAX) {
		yyerror("too many relays defined");
		goto err;
	}

	if (snprintf(rb->rl_conf.name, sizeof(rb->rl_conf.name), "%s%u:%u",
	    ra->rl_conf.name, rb->rl_conf.id, ntohs(rc.port)) >=
	    (int)sizeof(rb->rl_conf.name)) {
		yyerror("invalid relay name");
		goto err;
	}

	if (relay_findbyname(conf, rb->rl_conf.name) != NULL ||
	    relay_findbyaddr(conf, &rb->rl_conf) != NULL) {
		yyerror("relay %s defined twice", rb->rl_conf.name);
		goto err;
	}
	if (relay_load_certfiles(rb) == -1) {
		yyerror("cannot load certificates for relay %s",
		    rb->rl_conf.name);
		goto err;
	}

	TAILQ_FOREACH(rta, &ra->rl_tables, rlt_entry) {
		if ((rtb = calloc(1, sizeof(*rtb))) == NULL) {
			yyerror("cannot allocate relay table");
			goto err;
		}
		rtb->rlt_table = rta->rlt_table;
		rtb->rlt_mode = rta->rlt_mode;
		rtb->rlt_flags = rta->rlt_flags;

		TAILQ_INSERT_TAIL(&rb->rl_tables, rtb, rlt_entry);
	}

	conf->sc_relaycount++;
	SPLAY_INIT(&rlay->rl_sessions);
	TAILQ_INSERT_TAIL(conf->sc_relays, rb, rl_entry);

	return (rb);

 err:
	while ((rtb = TAILQ_FIRST(&rb->rl_tables))) {
		TAILQ_REMOVE(&rb->rl_tables, rtb, rlt_entry);
		free(rtb);
	}
	free(rb);
	return (NULL);
}

int
getservice(char *n)
{
	struct servent	*s;
	const char	*errstr;
	long long	 llval;

	llval = strtonum(n, 0, UINT16_MAX, &errstr);
	if (errstr) {
		s = getservbyname(n, "tcp");
		if (s == NULL)
			s = getservbyname(n, "udp");
		if (s == NULL) {
			yyerror("unknown port %s", n);
			return (-1);
		}
		return (s->s_port);
	}

	return (htons((u_short)llval));
}

int
is_if_in_group(const char *ifname, const char *groupname)
{
	unsigned int		 len;
	struct ifgroupreq	 ifgr;
	struct ifg_req		*ifg;
	int			 s;
	int			 ret = 0;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&ifgr, 0, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
		if (errno == EINVAL || errno == ENOTTY)
			goto end;
		err(1, "SIOCGIFGROUP");
	}

	len = ifgr.ifgr_len;
	ifgr.ifgr_groups =
	    (struct ifg_req *)calloc(len / sizeof(struct ifg_req),
		sizeof(struct ifg_req));
	if (ifgr.ifgr_groups == NULL)
		err(1, "getifgroups");
	if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1)
		err(1, "SIOCGIFGROUP");

	ifg = ifgr.ifgr_groups;
	for (; ifg && len >= sizeof(struct ifg_req); ifg++) {
		len -= sizeof(struct ifg_req);
		if (strcmp(ifg->ifgrq_group, groupname) == 0) {
			ret = 1;
			break;
		}
	}
	free(ifgr.ifgr_groups);

end:
	close(s);
	return (ret);
}
#line 2000 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || defined(__STDC__)
yyparse(void)
#else
yyparse()
#endif
{
    int yym, yyn, yystate;
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
    const char *yys;
#else /* !(defined(__cplusplus) || defined(__STDC__)) */
    char *yys;
#endif /* !(defined(__cplusplus) || defined(__STDC__)) */

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 11:
#line 188 "parse.y"
{ file->errors++; }
break;
case 12:
#line 191 "parse.y"
{
			struct file	*nfile;

			if ((nfile = pushfile(yyvsp[0].v.string, 0)) == NULL) {
				yyerror("failed to include file %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 13:
#line 206 "parse.y"
{ yyval.v.number = 0; }
break;
case 14:
#line 207 "parse.y"
{ yyval.v.number = 1; }
break;
case 15:
#line 210 "parse.y"
{ yyval.v.number = 0; }
break;
case 16:
#line 211 "parse.y"
{ yyval.v.number = 1; }
break;
case 17:
#line 214 "parse.y"
{
			if (strcmp("https", yyvsp[0].v.string) == 0) {
				yyval.v.number = 1;
			} else if (strcmp("http", yyvsp[0].v.string) == 0) {
				yyval.v.number = 0;
			} else {
				yyerror("invalid check type: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 18:
#line 228 "parse.y"
{
			yyval.v.string = strdup("");
			if (yyval.v.string == NULL)
				fatal("calloc");
		}
break;
case 19:
#line 233 "parse.y"
{
			if (asprintf(&yyval.v.string, "Host: %s\r\nConnection: close\r\n",
			    yyvsp[0].v.string) == -1)
				fatal("asprintf");
		}
break;
case 20:
#line 240 "parse.y"
{ yyval.v.number = RELAY_PROTO_TCP; }
break;
case 21:
#line 241 "parse.y"
{ yyval.v.number = RELAY_PROTO_TCP; }
break;
case 22:
#line 242 "parse.y"
{
			if (strcmp("http", yyvsp[0].v.string) == 0) {
				yyval.v.number = RELAY_PROTO_HTTP;
			} else if (strcmp("dns", yyvsp[0].v.string) == 0) {
				yyval.v.number = RELAY_PROTO_DNS;
			} else {
				yyerror("invalid protocol type: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 23:
#line 256 "parse.y"
{ yyval.v.number = IPPROTO_TCP; }
break;
case 24:
#line 257 "parse.y"
{ yyval.v.number = IPPROTO_TCP; }
break;
case 25:
#line 258 "parse.y"
{
			struct protoent	*p;

			if ((p = getprotobyname(yyvsp[0].v.string)) == NULL) {
				yyerror("invalid protocol: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			yyval.v.number = p->p_proto;
		}
break;
case 30:
#line 281 "parse.y"
{
			if ((proto->style = strdup(yyvsp[0].v.string)) == NULL)
				fatal("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 31:
#line 288 "parse.y"
{
			char		*a, *b;
			int		 p[2];

			p[0] = p[1] = 0;

			a = yyvsp[0].v.string;
			b = strchr(yyvsp[0].v.string, ':');
			if (b == NULL)
				yyval.v.port.op = PF_OP_EQ;
			else {
				*b++ = '\0';
				if ((p[1] = getservice(b)) == -1) {
					free(yyvsp[0].v.string);
					YYERROR;
				}
				yyval.v.port.op = PF_OP_RRG;
			}
			if ((p[0] = getservice(a)) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.port.val[0] = p[0];
			yyval.v.port.val[1] = p[1];
			free(yyvsp[0].v.string);
		}
break;
case 32:
#line 314 "parse.y"
{
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number >= (int)USHRT_MAX) {
				yyerror("invalid port: %d", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.port.val[0] = htons(yyvsp[0].v.number);
			yyval.v.port.op = PF_OP_EQ;
		}
break;
case 33:
#line 324 "parse.y"
{
			if (symset(yyvsp[-2].v.string, yyvsp[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 34:
#line 332 "parse.y"
{
			table->sendbuf = NULL;
		}
break;
case 35:
#line 335 "parse.y"
{
			table->sendbuf = strdup(yyvsp[0].v.string);
			if (table->sendbuf == NULL)
				fatal("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 36:
#line 343 "parse.y"
{
			if (loadcfg)
				break;
			if ((conf->sc_interval.tv_sec = yyvsp[0].v.number) < 0) {
				yyerror("invalid interval: %d", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 37:
#line 351 "parse.y"
{
			if (loadcfg)
				break;
			conf->sc_opts |= yyvsp[0].v.number;
		}
break;
case 38:
#line 356 "parse.y"
{
			if (loadcfg)
				break;
			bcopy(&yyvsp[0].v.tv, &conf->sc_timeout, sizeof(struct timeval));
		}
break;
case 39:
#line 361 "parse.y"
{
			if (loadcfg)
				break;
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number > RELAY_MAXPROC) {
				yyerror("invalid number of preforked "
				    "relays: %d", yyvsp[0].v.number);
				YYERROR;
			}
			conf->sc_prefork_relay = yyvsp[0].v.number;
		}
break;
case 40:
#line 371 "parse.y"
{
			if (loadcfg)
				break;
			conf->sc_flags |= F_TRAP;
		}
break;
case 41:
#line 378 "parse.y"
{ yyval.v.number = RELAYD_OPT_LOGUPDATE; }
break;
case 42:
#line 379 "parse.y"
{ yyval.v.number = RELAYD_OPT_LOGALL; }
break;
case 43:
#line 382 "parse.y"
{
			struct rdr *srv;

			conf->sc_flags |= F_NEEDPF;

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			TAILQ_FOREACH(srv, conf->sc_rdrs, entry)
				if (!strcmp(srv->conf.name, yyvsp[0].v.string))
					break;
			if (srv != NULL) {
				yyerror("redirection %s defined twice", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if ((srv = calloc(1, sizeof (*srv))) == NULL)
				fatal("out of memory");

			if (strlcpy(srv->conf.name, yyvsp[0].v.string,
			    sizeof(srv->conf.name)) >=
			    sizeof(srv->conf.name)) {
				yyerror("redirection name truncated");
				free(srv);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			srv->conf.id = ++last_rdr_id;
			srv->conf.timeout.tv_sec = RELAY_TIMEOUT;
			if (last_rdr_id == INT_MAX) {
				yyerror("too many redirections defined");
				free(srv);
				YYERROR;
			}
			rdr = srv;
		}
break;
case 44:
#line 419 "parse.y"
{
			if (rdr->table == NULL) {
				yyerror("redirection %s has no table",
				    rdr->conf.name);
				YYERROR;
			}
			if (TAILQ_EMPTY(&rdr->virts)) {
				yyerror("redirection %s has no virtual ip",
				    rdr->conf.name);
				YYERROR;
			}
			conf->sc_rdrcount++;
			if (rdr->backup == NULL) {
				rdr->conf.backup_id =
				    conf->sc_empty_table.conf.id;
				rdr->backup = &conf->sc_empty_table;
			} else if (rdr->backup->conf.port !=
			    rdr->table->conf.port) {
				yyerror("redirection %s uses two different "
				    "ports for its table and backup table",
				    rdr->conf.name);
				YYERROR;
			}
			if (!(rdr->conf.flags & F_DISABLE))
				rdr->conf.flags |= F_ADD;
			TAILQ_INSERT_TAIL(conf->sc_rdrs, rdr, entry);
			tableport = 0;
			rdr = NULL;
		}
break;
case 47:
#line 454 "parse.y"
{
			switch (yyvsp[-3].v.number) {
			case FWD_NORMAL:
				if (yyvsp[0].v.string == NULL)
					break;
				yyerror("superfluous interface");
				YYERROR;
			case FWD_ROUTE:
				if (yyvsp[0].v.string != NULL)
					break;
				yyerror("missing interface to route to");
				YYERROR;
			case FWD_TRANS:
				yyerror("no transparent forward here");
				YYERROR;
			}
			if (yyvsp[0].v.string != NULL) {
				strlcpy(yyvsp[-1].v.table->conf.ifname, yyvsp[0].v.string,
				    sizeof(yyvsp[-1].v.table->conf.ifname));
				free(yyvsp[0].v.string);
			}

			if (yyvsp[-1].v.table->conf.check == CHECK_NOCHECK) {
				yyerror("table %s has no check", yyvsp[-1].v.table->conf.name);
				purge_table(conf->sc_tables, yyvsp[-1].v.table);
				YYERROR;
			}
			if (rdr->backup) {
				yyerror("only one backup table is allowed");
				purge_table(conf->sc_tables, yyvsp[-1].v.table);
				YYERROR;
			}
			if (rdr->table) {
				rdr->backup = yyvsp[-1].v.table;
				rdr->conf.backup_id = yyvsp[-1].v.table->conf.id;
				if (dstmode != rdr->conf.mode) {
					yyerror("backup table for %s with "
					    "different mode", rdr->conf.name);
					YYERROR;
				}
			} else {
				rdr->table = yyvsp[-1].v.table;
				rdr->conf.table_id = yyvsp[-1].v.table->conf.id;
				rdr->conf.mode = dstmode;
			}
			yyvsp[-1].v.table->conf.fwdmode = yyvsp[-3].v.number;
			yyvsp[-1].v.table->conf.rdrid = rdr->conf.id;
			yyvsp[-1].v.table->conf.flags |= F_USED;
		}
break;
case 48:
#line 503 "parse.y"
{
			if (host(yyvsp[-3].v.string, &rdr->virts,
			    SRV_MAX_VIRTS, &yyvsp[-1].v.port, yyvsp[0].v.string, yyvsp[-2].v.number) <= 0) {
				yyerror("invalid virtual ip: %s", yyvsp[-3].v.string);
				free(yyvsp[-3].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[-3].v.string);
			free(yyvsp[0].v.string);
			if (rdr->conf.port == 0)
				rdr->conf.port = yyvsp[-1].v.port.val[0];
			tableport = rdr->conf.port;
		}
break;
case 49:
#line 517 "parse.y"
{ rdr->conf.flags |= F_DISABLE; }
break;
case 50:
#line 518 "parse.y"
{ rdr->conf.flags |= F_STICKY; }
break;
case 51:
#line 519 "parse.y"
{
			conf->sc_flags |= F_NEEDPF;
			if (strlcpy(rdr->conf.tag, yyvsp[0].v.string,
			    sizeof(rdr->conf.tag)) >=
			    sizeof(rdr->conf.tag)) {
				yyerror("redirection tag name truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (yyvsp[-2].v.number)
				rdr->conf.flags |= F_MATCH;
			free(yyvsp[0].v.string);
		}
break;
case 52:
#line 532 "parse.y"
{
			if ((rdr->conf.timeout.tv_sec = yyvsp[0].v.number) < 0) {
				yyerror("invalid timeout: %d", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 54:
#line 541 "parse.y"
{ yyval.v.number = 0; }
break;
case 55:
#line 542 "parse.y"
{ yyval.v.number = 1; }
break;
case 56:
#line 545 "parse.y"
{ yyval.v.number = FWD_NORMAL; }
break;
case 57:
#line 546 "parse.y"
{ yyval.v.number = FWD_ROUTE; }
break;
case 58:
#line 547 "parse.y"
{ yyval.v.number = FWD_TRANS; }
break;
case 59:
#line 550 "parse.y"
{
			if (strlen(yyvsp[-1].v.string) >= TABLE_NAME_SIZE) {
				yyerror("invalid table name");
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			yyval.v.string = yyvsp[-1].v.string;
		}
break;
case 60:
#line 560 "parse.y"
{
			struct table *tb;

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			TAILQ_FOREACH(tb, conf->sc_tables, entry)
				if (!strcmp(tb->conf.name, yyvsp[0].v.string))
					break;
			if (tb != NULL) {
				yyerror("table %s defined twice", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if ((tb = calloc(1, sizeof (*tb))) == NULL)
				fatal("out of memory");

			(void)strlcpy(tb->conf.name, yyvsp[0].v.string, sizeof(tb->conf.name));
			free(yyvsp[0].v.string);

			tb->conf.id = 0; /* will be set later */
			bcopy(&conf->sc_timeout, &tb->conf.timeout,
			    sizeof(struct timeval));
			TAILQ_INIT(&tb->hosts);
			table = tb;
			dstmode = RELAY_DSTMODE_DEFAULT;
		}
break;
case 61:
#line 589 "parse.y"
{
			if (TAILQ_EMPTY(&table->hosts)) {
				yyerror("table %s has no hosts",
				    table->conf.name);
				YYERROR;
			}
			conf->sc_tablecount++;
			TAILQ_INSERT_TAIL(conf->sc_tables, table, entry);
		}
break;
case 64:
#line 604 "parse.y"
{ table->conf.flags |= F_DISABLE; }
break;
case 68:
#line 612 "parse.y"
{
			yyvsp[0].v.host->conf.tableid = table->conf.id;
			yyvsp[0].v.host->tablename = table->conf.name;
			TAILQ_INSERT_TAIL(&table->hosts, yyvsp[0].v.host, entry);
		}
break;
case 70:
#line 620 "parse.y"
{
			struct table	*tb;
			if ((tb = calloc(1, sizeof (*tb))) == NULL)
				fatal("out of memory");
			(void)strlcpy(tb->conf.name, yyvsp[0].v.string, sizeof(tb->conf.name));
			free(yyvsp[0].v.string);
			table = tb;
		}
break;
case 71:
#line 627 "parse.y"
{
			struct table	*tb;
			if (table->conf.port == 0)
				table->conf.port = tableport;
			else
				table->conf.flags |= F_PORT;
			if ((tb = table_inherit(table)) == NULL)
				YYERROR;
			yyval.v.table = tb;
		}
break;
case 75:
#line 644 "parse.y"
{
			if (yyvsp[0].v.port.op != PF_OP_EQ) {
				yyerror("invalid port");
				YYERROR;
			}
			table->conf.port = yyvsp[0].v.port.val[0];
		}
break;
case 76:
#line 651 "parse.y"
{
			bcopy(&yyvsp[0].v.tv, &table->conf.timeout,
			    sizeof(struct timeval));
		}
break;
case 77:
#line 655 "parse.y"
{
			table->conf.flags |= F_DEMOTE;
			if (strlcpy(table->conf.demote_group, yyvsp[0].v.string,
			    sizeof(table->conf.demote_group))
			    >= sizeof(table->conf.demote_group)) {
				yyerror("yyparse: demote group name too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			if (carp_demote_init(table->conf.demote_group, 1)
			    == -1) {
				yyerror("yyparse: error initializing group "
				    "'%s'", table->conf.demote_group);
				YYERROR;
			}
		}
break;
case 78:
#line 672 "parse.y"
{
			if (yyvsp[0].v.number < conf->sc_interval.tv_sec ||
			    yyvsp[0].v.number % conf->sc_interval.tv_sec) {
				yyerror("table interval must be "
				    "divisible by global interval");
				YYERROR;
			}
			table->conf.skip_cnt =
			    (yyvsp[0].v.number / conf->sc_interval.tv_sec) - 1;
		}
break;
case 79:
#line 682 "parse.y"
{
			switch (yyvsp[0].v.number) {
			case RELAY_DSTMODE_LOADBALANCE:
			case RELAY_DSTMODE_HASH:
			case RELAY_DSTMODE_SRCHASH:
			case RELAY_DSTMODE_RANDOM:
				if (rdr != NULL) {
					yyerror("mode not supported "
					    "for redirections");
					YYERROR;
				}
				/* FALLTHROUGH */
			case RELAY_DSTMODE_ROUNDROBIN:
				dstmode = yyvsp[0].v.number;
				break;
			case RELAY_DSTMODE_LEASTSTATES:
				if (rdr == NULL) {
					yyerror("mode not supported "
					    "for relays");
					YYERROR;
				}
				dstmode = yyvsp[0].v.number;
				break;
			}
		}
break;
case 80:
#line 709 "parse.y"
{ table->conf.check = CHECK_ICMP; }
break;
case 81:
#line 710 "parse.y"
{ table->conf.check = CHECK_TCP; }
break;
case 82:
#line 711 "parse.y"
{
			table->conf.check = CHECK_TCP;
			conf->sc_flags |= F_SSL;
			table->conf.flags |= F_SSL;
		}
break;
case 83:
#line 716 "parse.y"
{
			if (yyvsp[-4].v.number) {
				conf->sc_flags |= F_SSL;
				table->conf.flags |= F_SSL;
			}
			table->conf.check = CHECK_HTTP_CODE;
			if ((table->conf.retcode = yyvsp[0].v.number) <= 0) {
				yyerror("invalid HTTP code: %d", yyvsp[0].v.number);
				free(yyvsp[-3].v.string);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			if (asprintf(&table->sendbuf,
			    "HEAD %s HTTP/1.%c\r\n%s\r\n",
			    yyvsp[-3].v.string, strlen(yyvsp[-2].v.string) ? '1' : '0', yyvsp[-2].v.string) == -1)
				fatal("asprintf");
			free(yyvsp[-3].v.string);
			free(yyvsp[-2].v.string);
			if (table->sendbuf == NULL)
				fatal("out of memory");
		}
break;
case 84:
#line 737 "parse.y"
{
			if (yyvsp[-3].v.number) {
				conf->sc_flags |= F_SSL;
				table->conf.flags |= F_SSL;
			}
			table->conf.check = CHECK_HTTP_DIGEST;
			if (asprintf(&table->sendbuf,
			    "GET %s HTTP/1.%c\r\n%s\r\n",
			    yyvsp[-2].v.string, strlen(yyvsp[-1].v.string) ? '1' : '0', yyvsp[-1].v.string) == -1)
				fatal("asprintf");
			free(yyvsp[-2].v.string);
			free(yyvsp[-1].v.string);
			if (table->sendbuf == NULL)
				fatal("out of memory");
			(void)strlcpy(table->conf.digest, yyvsp[0].v.digest.digest,
			    sizeof(table->conf.digest));
			table->conf.digest_type = yyvsp[0].v.digest.type;
			free(yyvsp[0].v.digest.digest);
		}
break;
case 85:
#line 756 "parse.y"
{
			table->conf.check = CHECK_SEND_EXPECT;
			if (yyvsp[0].v.number) {
				conf->sc_flags |= F_SSL;
				table->conf.flags |= F_SSL;
			}
			if (strlcpy(table->conf.exbuf, yyvsp[-1].v.string,
			    sizeof(table->conf.exbuf))
			    >= sizeof(table->conf.exbuf)) {
				yyerror("yyparse: expect buffer truncated");
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			translate_string(table->conf.exbuf);
			free(yyvsp[-1].v.string);
		}
break;
case 86:
#line 772 "parse.y"
{
			table->conf.check = CHECK_SCRIPT;
			if (strlcpy(table->conf.path, yyvsp[0].v.string,
			    sizeof(table->conf.path)) >=
			    sizeof(table->conf.path)) {
				yyerror("script path truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			conf->sc_flags |= F_SCRIPT;
			free(yyvsp[0].v.string);
		}
break;
case 87:
#line 787 "parse.y"
{
			switch (strlen(yyvsp[0].v.string)) {
			case 40:
				yyval.v.digest.type = DIGEST_SHA1;
				break;
			case 32:
				yyval.v.digest.type = DIGEST_MD5;
				break;
			default:
				yyerror("invalid http digest");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.digest.digest = yyvsp[0].v.string;
		}
break;
case 88:
#line 804 "parse.y"
{
			struct protocol *p;

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			if (strcmp(yyvsp[0].v.string, "default") == 0) {
				p = &conf->sc_proto_default;
			} else {
				TAILQ_FOREACH(p, conf->sc_protos, entry)
					if (!strcmp(p->name, yyvsp[0].v.string))
						break;
			}
			if (p != NULL) {
				yyerror("protocol %s defined twice", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if ((p = calloc(1, sizeof (*p))) == NULL)
				fatal("out of memory");

			if (strlcpy(p->name, yyvsp[0].v.string, sizeof(p->name)) >=
			    sizeof(p->name)) {
				yyerror("protocol name truncated");
				free(p);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			p->id = ++last_proto_id;
			p->type = yyvsp[-2].v.number;
			p->cache = RELAY_CACHESIZE;
			p->tcpflags = TCPFLAG_DEFAULT;
			p->sslflags = SSLFLAG_DEFAULT;
			p->tcpbacklog = RELAY_BACKLOG;
			(void)strlcpy(p->sslciphers, SSLCIPHERS_DEFAULT,
			    sizeof(p->sslciphers));
			if (last_proto_id == INT_MAX) {
				yyerror("too many protocols defined");
				free(p);
				YYERROR;
			}
			RB_INIT(&p->request_tree);
			RB_INIT(&p->response_tree);
			proto = p;
		}
break;
case 89:
#line 850 "parse.y"
{
			conf->sc_protocount++;

			if ((proto->sslflags & SSLFLAG_VERSION) == 0) {
				yyerror("invalid SSL protocol");
				YYERROR;
			}

			TAILQ_INSERT_TAIL(conf->sc_protos, proto, entry);
		}
break;
case 99:
#line 875 "parse.y"
{ proto->flags |= F_RETURN; }
break;
case 100:
#line 876 "parse.y"
{ proto->flags |= F_RETURN; }
break;
case 101:
#line 877 "parse.y"
{
			label = pn_name2id(yyvsp[0].v.string);
			free(yyvsp[0].v.string);
			if (label == 0) {
				yyerror("invalid protocol action label");
				YYERROR;
			}
		}
break;
case 102:
#line 885 "parse.y"
{
			label = 0;
		}
break;
case 103:
#line 888 "parse.y"
{
			node.label = label;
			node.labelname = NULL;
			nodedirection = yyvsp[0].v.number;
		}
break;
case 104:
#line 892 "parse.y"
{
			if (nodedirection != -1 &&
			    protonode_add(nodedirection, proto, &node) == -1) {
				yyerror("failed to add protocol node");
				YYERROR;
			}
			bzero(&node, sizeof(node));
		}
break;
case 106:
#line 903 "parse.y"
{ yyval.v.number = RELAY_DIR_REQUEST; }
break;
case 107:
#line 904 "parse.y"
{ yyval.v.number = RELAY_DIR_REQUEST; }
break;
case 108:
#line 905 "parse.y"
{ yyval.v.number = RELAY_DIR_RESPONSE; }
break;
case 111:
#line 912 "parse.y"
{ proto->tcpflags |= TCPFLAG_SACK; }
break;
case 112:
#line 913 "parse.y"
{ proto->tcpflags |= TCPFLAG_NSACK; }
break;
case 113:
#line 914 "parse.y"
{ proto->tcpflags |= TCPFLAG_NODELAY; }
break;
case 114:
#line 915 "parse.y"
{ proto->tcpflags |= TCPFLAG_NNODELAY; }
break;
case 115:
#line 916 "parse.y"
{ /* default */ }
break;
case 116:
#line 917 "parse.y"
{ proto->tcpflags |= TCPFLAG_NSPLICE; }
break;
case 117:
#line 918 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > RELAY_MAX_SESSIONS) {
				yyerror("invalid backlog: %d", yyvsp[0].v.number);
				YYERROR;
			}
			proto->tcpbacklog = yyvsp[0].v.number;
		}
break;
case 118:
#line 925 "parse.y"
{
			proto->tcpflags |= TCPFLAG_BUFSIZ;
			if ((proto->tcpbufsiz = yyvsp[0].v.number) < 0) {
				yyerror("invalid socket buffer size: %d", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 119:
#line 932 "parse.y"
{
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid ttl: %d", yyvsp[0].v.number);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (strcasecmp("ttl", yyvsp[-1].v.string) == 0) {
				proto->tcpflags |= TCPFLAG_IPTTL;
				proto->tcpipttl = yyvsp[0].v.number;
			} else if (strcasecmp("minttl", yyvsp[-1].v.string) == 0) {
				proto->tcpflags |= TCPFLAG_IPMINTTL;
				proto->tcpipminttl = yyvsp[0].v.number;
			} else {
				yyerror("invalid TCP/IP flag: %s", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 122:
#line 957 "parse.y"
{ proto->cache = yyvsp[0].v.number; }
break;
case 123:
#line 958 "parse.y"
{
			if (strlcpy(proto->sslciphers, yyvsp[0].v.string,
			    sizeof(proto->sslciphers)) >=
			    sizeof(proto->sslciphers)) {
				yyerror("sslciphers truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 124:
#line 968 "parse.y"
{
			if (strlcpy(proto->sslca, yyvsp[0].v.string,
			    sizeof(proto->sslca)) >=
			    sizeof(proto->sslca)) {
				yyerror("sslca truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 125:
#line 978 "parse.y"
{ proto->sslflags &= ~(yyvsp[0].v.number); }
break;
case 126:
#line 979 "parse.y"
{ proto->sslflags |= yyvsp[0].v.number; }
break;
case 127:
#line 982 "parse.y"
{
			if (strcmp("sslv2", yyvsp[0].v.string) == 0)
				yyval.v.number = SSLFLAG_SSLV2;
			else if (strcmp("sslv3", yyvsp[0].v.string) == 0)
				yyval.v.number = SSLFLAG_SSLV3;
			else if (strcmp("tlsv1", yyvsp[0].v.string) == 0)
				yyval.v.number = SSLFLAG_TLSV1;
			else {
				yyerror("invalid SSL flag: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 128:
#line 998 "parse.y"
{
			node.action = NODE_ACTION_APPEND;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = strdup(yyvsp[-3].v.string);
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			if (strchr(node.value, '$') != NULL)
				node.flags |= PNFLAG_MACRO;
			free(yyvsp[-1].v.string);
			free(yyvsp[-3].v.string);
		}
break;
case 129:
#line 1009 "parse.y"
{
			node.action = NODE_ACTION_CHANGE;
			node.key = strdup(yyvsp[-3].v.string);
			node.value = strdup(yyvsp[-1].v.string);
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			if (strchr(node.value, '$') != NULL)
				node.flags |= PNFLAG_MACRO;
			free(yyvsp[-1].v.string);
			free(yyvsp[-3].v.string);
		}
break;
case 130:
#line 1020 "parse.y"
{
			node.action = NODE_ACTION_REMOVE;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = NULL;
			if (node.key == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
		}
break;
case 131:
#line 1028 "parse.y"
{
			node.action = NODE_ACTION_REMOVE;
			node.key = NULL;
			node.value = NULL;
		}
break;
case 133:
#line 1033 "parse.y"
{
			node.action = NODE_ACTION_EXPECT;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = strdup(yyvsp[-3].v.string);
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
			free(yyvsp[-3].v.string);
			proto->lateconnect++;
		}
break;
case 134:
#line 1043 "parse.y"
{
			node.action = NODE_ACTION_EXPECT;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = strdup("*");
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
			proto->lateconnect++;
		}
break;
case 135:
#line 1052 "parse.y"
{
			node.action = NODE_ACTION_EXPECT;
			node.key = NULL;
			node.value = "*";
			proto->lateconnect++;
		}
break;
case 137:
#line 1058 "parse.y"
{
			if (node.type != NODE_TYPE_URL) {
				yyerror("digest not supported for this type");
				free(yyvsp[-1].v.digest.digest);
				YYERROR;
			}
			node.action = NODE_ACTION_EXPECT;
			node.key = strdup(yyvsp[-1].v.digest.digest);
			node.flags |= PNFLAG_LOOKUP_DIGEST(yyvsp[-1].v.digest.type);
			node.value = strdup("*");
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.digest.digest);
			proto->lateconnect++;
		}
break;
case 138:
#line 1073 "parse.y"
{
			node.action = NODE_ACTION_FILTER;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = strdup(yyvsp[-3].v.string);
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
			free(yyvsp[-3].v.string);
			proto->lateconnect++;
		}
break;
case 139:
#line 1083 "parse.y"
{
			node.action = NODE_ACTION_FILTER;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = strdup("*");
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
			proto->lateconnect++;
		}
break;
case 140:
#line 1092 "parse.y"
{
			node.action = NODE_ACTION_FILTER;
			node.key = NULL;
			node.value = "*";
			proto->lateconnect++;
		}
break;
case 142:
#line 1098 "parse.y"
{
			if (node.type != NODE_TYPE_URL) {
				yyerror("digest not supported for this type");
				free(yyvsp[-1].v.digest.digest);
				YYERROR;
			}
			node.action = NODE_ACTION_FILTER;
			node.key = strdup(yyvsp[-1].v.digest.digest);
			node.flags |= PNFLAG_LOOKUP_DIGEST(yyvsp[-1].v.digest.type);
			node.value = strdup("*");
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.digest.digest);
			proto->lateconnect++;
		}
break;
case 143:
#line 1113 "parse.y"
{
			node.action = NODE_ACTION_HASH;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = NULL;
			if (node.key == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
			proto->lateconnect++;
		}
break;
case 144:
#line 1122 "parse.y"
{
			node.action = NODE_ACTION_LOG;
			node.key = strdup(yyvsp[-1].v.string);
			node.value = NULL;
			node.flags |= PNFLAG_LOG;
			if (node.key == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
		}
break;
case 145:
#line 1131 "parse.y"
{
			node.action = NODE_ACTION_LOG;
			node.key = NULL;
			node.value = NULL;
			node.flags |= PNFLAG_LOG;
		}
break;
case 147:
#line 1137 "parse.y"
{
			node.action = NODE_ACTION_MARK;
			node.key = strdup(yyvsp[-3].v.string);
			node.value = strdup(yyvsp[-5].v.string);
			node.mark = yyvsp[-1].v.number;
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-5].v.string);
			free(yyvsp[-3].v.string);
		}
break;
case 148:
#line 1147 "parse.y"
{
			node.action = NODE_ACTION_MARK;
			node.key = strdup(yyvsp[-3].v.string);
			node.value = strdup("*");
			node.mark = yyvsp[-1].v.number;	/* overwrite */
			if (node.key == NULL || node.value == NULL)
				fatal("out of memory");
			free(yyvsp[-3].v.string);
		}
break;
case 149:
#line 1158 "parse.y"
{
			if (protonode_load(nodedirection,
			    proto, &node, yyvsp[-1].v.string) == -1) {
				yyerror("failed to load from file: %s", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
			nodedirection = -1;	/* don't add template node */
		}
break;
case 152:
#line 1174 "parse.y"
{ node.mark = yyvsp[0].v.number; }
break;
case 154:
#line 1178 "parse.y"
{ node.flags |= PNFLAG_LOG; }
break;
case 155:
#line 1181 "parse.y"
{
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number >= (int)USHRT_MAX) {
				yyerror("invalid mark: %d", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number;
		}
break;
case 156:
#line 1190 "parse.y"
{
			node.type = NODE_TYPE_HEADER;
		}
break;
case 157:
#line 1193 "parse.y"
{ node.type = NODE_TYPE_QUERY; }
break;
case 158:
#line 1194 "parse.y"
{
			node.type = NODE_TYPE_COOKIE;
		}
break;
case 159:
#line 1197 "parse.y"
{
			proto->flags |= F_LOOKUP_PATH;
			node.type = NODE_TYPE_PATH;
		}
break;
case 160:
#line 1201 "parse.y"
{ node.type = NODE_TYPE_URL; }
break;
case 161:
#line 1204 "parse.y"
{
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid sslcache value: %d", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number;
		}
break;
case 162:
#line 1211 "parse.y"
{ yyval.v.number = -2; }
break;
case 163:
#line 1214 "parse.y"
{
			struct relay *r;

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			TAILQ_FOREACH(r, conf->sc_relays, rl_entry)
				if (!strcmp(r->rl_conf.name, yyvsp[0].v.string))
					break;
			if (r != NULL) {
				yyerror("relay %s defined twice", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			TAILQ_INIT(&relays);

			if ((r = calloc(1, sizeof (*r))) == NULL)
				fatal("out of memory");

			if (strlcpy(r->rl_conf.name, yyvsp[0].v.string,
			    sizeof(r->rl_conf.name)) >=
			    sizeof(r->rl_conf.name)) {
				yyerror("relay name truncated");
				free(r);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			r->rl_conf.id = ++last_relay_id;
			r->rl_conf.timeout.tv_sec = RELAY_TIMEOUT;
			r->rl_proto = NULL;
			r->rl_conf.proto = EMPTY_ID;
			r->rl_conf.dstretry = 0;
			TAILQ_INIT(&r->rl_tables);
			if (last_relay_id == INT_MAX) {
				yyerror("too many relays defined");
				free(r);
				YYERROR;
			}
			dstmode = RELAY_DSTMODE_DEFAULT;
			rlay = r;
		}
break;
case 164:
#line 1256 "parse.y"
{
			struct relay	*r;

			if (rlay->rl_conf.ss.ss_family == AF_UNSPEC) {
				yyerror("relay %s has no listener",
				    rlay->rl_conf.name);
				YYERROR;
			}
			if ((rlay->rl_conf.flags & (F_NATLOOK|F_DIVERT)) ==
			    (F_NATLOOK|F_DIVERT)) {
				yyerror("relay %s with conflicting nat lookup "
				    "and peer options", rlay->rl_conf.name);
				YYERROR;
			}
			if ((rlay->rl_conf.flags & (F_NATLOOK|F_DIVERT)) == 0 &&
			    rlay->rl_conf.dstss.ss_family == AF_UNSPEC &&
			    TAILQ_EMPTY(&rlay->rl_tables)) {
				yyerror("relay %s has no target, rdr, "
				    "or table", rlay->rl_conf.name);
				YYERROR;
			}
			if (rlay->rl_conf.proto == EMPTY_ID) {
				rlay->rl_proto = &conf->sc_proto_default;
				rlay->rl_conf.proto = conf->sc_proto_default.id;
			}
			if (relay_load_certfiles(rlay) == -1) {
				yyerror("cannot load certificates for relay %s",
				    rlay->rl_conf.name);
				YYERROR;
			}
			conf->sc_relaycount++;
			SPLAY_INIT(&rlay->rl_sessions);
			TAILQ_INSERT_TAIL(conf->sc_relays, rlay, rl_entry);

			tableport = 0;

			while ((r = TAILQ_FIRST(&relays)) != NULL) {
				TAILQ_REMOVE(&relays, r, rl_entry);
				if (relay_inherit(rlay, r) == NULL) {
					YYERROR;
				}
			}
			rlay = NULL;
		}
break;
case 167:
#line 1306 "parse.y"
{
			struct addresslist	 al;
			struct address		*h;
			struct relay		*r;

			if (rlay->rl_conf.ss.ss_family != AF_UNSPEC) {
				if ((r = calloc(1, sizeof (*r))) == NULL)
					fatal("out of memory");
				TAILQ_INSERT_TAIL(&relays, r, rl_entry);
			} else
				r = rlay;
			if (yyvsp[-1].v.port.op != PF_OP_EQ) {
				yyerror("invalid port");
				free(yyvsp[-2].v.string);
				YYERROR;
			}

			TAILQ_INIT(&al);
			if (host(yyvsp[-2].v.string, &al, 1, &yyvsp[-1].v.port, NULL, -1) <= 0) {
				yyerror("invalid listen ip: %s", yyvsp[-2].v.string);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			h = TAILQ_FIRST(&al);
			bcopy(&h->ss, &r->rl_conf.ss, sizeof(r->rl_conf.ss));
			r->rl_conf.port = h->port.val[0];
			if (yyvsp[0].v.number) {
				r->rl_conf.flags |= F_SSL;
				conf->sc_flags |= F_SSL;
			}
			tableport = h->port.val[0];
			host_free(&al);
		}
break;
case 168:
#line 1340 "parse.y"
{
			rlay->rl_conf.fwdmode = yyvsp[-5].v.number;
			switch (yyvsp[-5].v.number) {
			case FWD_NORMAL:
				if (yyvsp[-1].v.string == NULL)
					break;
				yyerror("superfluous interface");
				YYERROR;
			case FWD_ROUTE:
				yyerror("no route for redirections");
				YYERROR;
			case FWD_TRANS:
				if (yyvsp[-1].v.string != NULL)
					break;
				yyerror("missing interface");
				YYERROR;
			}
			if (yyvsp[-1].v.string != NULL) {
				strlcpy(rlay->rl_conf.ifname, yyvsp[-1].v.string,
				    sizeof(rlay->rl_conf.ifname));
				free(yyvsp[-1].v.string);
			}
			if (yyvsp[-4].v.number) {
				rlay->rl_conf.flags |= F_SSLCLIENT;
				conf->sc_flags |= F_SSLCLIENT;
			}
		}
break;
case 169:
#line 1367 "parse.y"
{
			if ((rlay->rl_conf.timeout.tv_sec = yyvsp[0].v.number) < 0) {
				yyerror("invalid timeout: %d", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 170:
#line 1373 "parse.y"
{
			struct protocol *p;

			TAILQ_FOREACH(p, conf->sc_protos, entry)
				if (!strcmp(p->name, yyvsp[0].v.string))
					break;
			if (p == NULL) {
				yyerror("no such protocol: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			p->flags |= F_USED;
			rlay->rl_conf.proto = p->id;
			rlay->rl_proto = p;
			free(yyvsp[0].v.string);
		}
break;
case 171:
#line 1389 "parse.y"
{ rlay->rl_conf.flags |= F_DISABLE; }
break;
case 173:
#line 1393 "parse.y"
{
			struct addresslist	 al;
			struct address		*h;

			if (rlay->rl_conf.dstss.ss_family != AF_UNSPEC) {
				yyerror("relay %s target or redirection "
				    "already specified", rlay->rl_conf.name);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			if (yyvsp[-1].v.port.op != PF_OP_EQ) {
				yyerror("invalid port");
				free(yyvsp[-2].v.string);
				YYERROR;
			}

			TAILQ_INIT(&al);
			if (host(yyvsp[-2].v.string, &al, 1, &yyvsp[-1].v.port, NULL, -1) <= 0) {
				yyerror("invalid listen ip: %s", yyvsp[-2].v.string);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			h = TAILQ_FIRST(&al);
			bcopy(&h->ss, &rlay->rl_conf.dstss,
			    sizeof(rlay->rl_conf.dstss));
			rlay->rl_conf.dstport = h->port.val[0];
			rlay->rl_conf.dstretry = yyvsp[0].v.number;
			host_free(&al);
		}
break;
case 174:
#line 1423 "parse.y"
{
			conf->sc_flags |= F_NEEDPF;
			rlay->rl_conf.flags |= F_NATLOOK;
			rlay->rl_conf.dstretry = yyvsp[0].v.number;
		}
break;
case 175:
#line 1428 "parse.y"
{
			conf->sc_flags |= F_NEEDPF;
			rlay->rl_conf.flags |= F_DIVERT;
			rlay->rl_conf.dstretry = yyvsp[0].v.number;
		}
break;
case 176:
#line 1433 "parse.y"
{
			struct relay_table	*rlt;

			if ((rlt = calloc(1, sizeof(*rlt))) == NULL) {
				yyerror("failed to allocate table reference");
				YYERROR;
			}

			rlt->rlt_table = yyvsp[0].v.table;
			rlt->rlt_table->conf.flags |= F_USED;
			rlt->rlt_mode = dstmode;
			rlt->rlt_flags = F_USED;
			if (!TAILQ_EMPTY(&rlay->rl_tables))
				rlt->rlt_flags |= F_BACKUP;

			TAILQ_INSERT_TAIL(&rlay->rl_tables, rlt, rlt_entry);
		}
break;
case 177:
#line 1452 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_DEFAULT; }
break;
case 178:
#line 1453 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_LOADBALANCE; }
break;
case 179:
#line 1454 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_ROUNDROBIN; }
break;
case 180:
#line 1455 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_HASH; }
break;
case 181:
#line 1456 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_LEASTSTATES; }
break;
case 182:
#line 1457 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_SRCHASH; }
break;
case 183:
#line 1458 "parse.y"
{ yyval.v.number = RELAY_DSTMODE_RANDOM; }
break;
case 184:
#line 1461 "parse.y"
{
			struct router *rt = NULL;

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			conf->sc_flags |= F_NEEDRT;
			TAILQ_FOREACH(rt, conf->sc_rts, rt_entry)
				if (!strcmp(rt->rt_conf.name, yyvsp[0].v.string))
					break;
			if (rt != NULL) {
				yyerror("router %s defined twice", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if ((rt = calloc(1, sizeof (*rt))) == NULL)
				fatal("out of memory");

			if (strlcpy(rt->rt_conf.name, yyvsp[0].v.string,
			    sizeof(rt->rt_conf.name)) >=
			    sizeof(rt->rt_conf.name)) {
				yyerror("router name truncated");
				free(rt);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			rt->rt_conf.id = ++last_rt_id;
			if (last_rt_id == INT_MAX) {
				yyerror("too many routers defined");
				free(rt);
				YYERROR;
			}
			TAILQ_INIT(&rt->rt_netroutes);
			router = rt;

			tableport = -1;
		}
break;
case 185:
#line 1500 "parse.y"
{
			if (!router->rt_conf.nroutes) {
				yyerror("router %s without routes",
				    router->rt_conf.name);
				free(router);
				router = NULL;
				YYERROR;
			}

			conf->sc_routercount++;
			TAILQ_INSERT_TAIL(conf->sc_rts, router, rt_entry);
			router = NULL;

			tableport = 0;
		}
break;
case 188:
#line 1521 "parse.y"
{
			struct netroute	*nr;

			if (router->rt_conf.af == AF_UNSPEC)
				router->rt_conf.af = yyvsp[-2].v.addr.ss.ss_family;
			else if (router->rt_conf.af != yyvsp[-2].v.addr.ss.ss_family) {
				yyerror("router %s address family mismatch",
				    router->rt_conf.name);
				YYERROR;
			}

			if ((router->rt_conf.af == AF_INET &&
			    (yyvsp[0].v.number > 32 || yyvsp[0].v.number < 0)) ||
			    (router->rt_conf.af == AF_INET6 &&
			    (yyvsp[0].v.number > 128 || yyvsp[0].v.number < 0))) {
				yyerror("invalid prefixlen %d", yyvsp[0].v.number);
				YYERROR;
			}

			if ((nr = calloc(1, sizeof(*nr))) == NULL)
				fatal("out of memory");

			nr->nr_conf.id = ++last_nr_id;
			if (last_nr_id == INT_MAX) {
				yyerror("too many routes defined");
				free(nr);
				YYERROR;
			}
			nr->nr_conf.prefixlen = yyvsp[0].v.number;
			nr->nr_conf.routerid = router->rt_conf.id;
			nr->nr_router = router;
			bcopy(&yyvsp[-2].v.addr.ss, &nr->nr_conf.ss, sizeof(yyvsp[-2].v.addr.ss));

			router->rt_conf.nroutes++;
			conf->sc_routecount++;
			TAILQ_INSERT_TAIL(&router->rt_netroutes, nr, nr_entry);
			TAILQ_INSERT_TAIL(conf->sc_routes, nr, nr_route);
		}
break;
case 189:
#line 1559 "parse.y"
{
			if (router->rt_gwtable) {
				yyerror("router %s table already specified",
				    router->rt_conf.name);
				purge_table(conf->sc_tables, yyvsp[0].v.table);
				YYERROR;
			}
			router->rt_gwtable = yyvsp[0].v.table;
			router->rt_gwtable->conf.flags |= F_USED;
			router->rt_conf.gwtable = yyvsp[0].v.table->conf.id;
			router->rt_conf.gwport = yyvsp[0].v.table->conf.port;
		}
break;
case 190:
#line 1571 "parse.y"
{
			if (router->rt_conf.rtable) {
				yyerror("router %s rtable already specified",
				    router->rt_conf.name);
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > RT_TABLEID_MAX) {
				yyerror("invalid rtable id %d", yyvsp[0].v.number);
				YYERROR;
			}
			router->rt_conf.rtable = yyvsp[0].v.number;
		}
break;
case 191:
#line 1583 "parse.y"
{
			if (strlcpy(router->rt_conf.label, yyvsp[0].v.string,
			    sizeof(router->rt_conf.label)) >=
			    sizeof(router->rt_conf.label)) {
				yyerror("route label truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 192:
#line 1593 "parse.y"
{ rlay->rl_conf.flags |= F_DISABLE; }
break;
case 194:
#line 1597 "parse.y"
{
			rlay->rl_conf.dstaf.ss_family = AF_UNSPEC;
		}
break;
case 195:
#line 1600 "parse.y"
{
			rlay->rl_conf.dstaf.ss_family = AF_INET;
		}
break;
case 196:
#line 1603 "parse.y"
{
			struct sockaddr_in6	*sin6;

			sin6 = (struct sockaddr_in6 *)&rlay->rl_conf.dstaf;
			if (inet_pton(AF_INET6, yyvsp[0].v.string, &sin6->sin6_addr) == -1) {
				yyerror("invalid ipv6 address %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
		}
break;
case 197:
#line 1619 "parse.y"
{ yyval.v.string = NULL; }
break;
case 198:
#line 1620 "parse.y"
{ yyval.v.string = yyvsp[0].v.string; }
break;
case 199:
#line 1623 "parse.y"
{
			if ((hst = calloc(1, sizeof(*(hst)))) == NULL)
				fatal("out of memory");

			if (strlcpy(hst->conf.name, yyvsp[0].v.addr.name,
			    sizeof(hst->conf.name)) >= sizeof(hst->conf.name)) {
				yyerror("host name truncated");
				free(hst);
				YYERROR;
			}
			bcopy(&yyvsp[0].v.addr.ss, &hst->conf.ss, sizeof(yyvsp[0].v.addr.ss));
			hst->conf.id = 0; /* will be set later */
			SLIST_INIT(&hst->children);
		}
break;
case 200:
#line 1636 "parse.y"
{
			yyval.v.host = hst;
			hst = NULL;
		}
break;
case 205:
#line 1650 "parse.y"
{
			if (hst->conf.retry) {
				yyerror("retry value already set");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid retry value: %d\n", yyvsp[0].v.number);
				YYERROR;
			}
			hst->conf.retry = yyvsp[0].v.number;
		}
break;
case 206:
#line 1661 "parse.y"
{
			if (hst->conf.parentid) {
				yyerror("parent value already set");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid parent value: %d\n", yyvsp[0].v.number);
				YYERROR;
			}
			hst->conf.parentid = yyvsp[0].v.number;
		}
break;
case 207:
#line 1672 "parse.y"
{
			if (hst->conf.priority) {
				yyerror("priority already set");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > RTP_MAX) {
				yyerror("invalid priority value: %d\n", yyvsp[0].v.number);
				YYERROR;
			}
			hst->conf.priority = yyvsp[0].v.number;
		}
break;
case 208:
#line 1683 "parse.y"
{
			if (hst->conf.ttl) {
				yyerror("ttl value already set");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid ttl value: %d\n", yyvsp[0].v.number);
				YYERROR;
			}
			hst->conf.ttl = yyvsp[0].v.number;
		}
break;
case 209:
#line 1696 "parse.y"
{
			struct address *h;
			struct addresslist al;

			if (strlcpy(yyval.v.addr.name, yyvsp[0].v.string,
			    sizeof(yyval.v.addr.name)) >= sizeof(yyval.v.addr.name)) {
				yyerror("host name truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}

			TAILQ_INIT(&al);
			if (host(yyvsp[0].v.string, &al, 1, NULL, NULL, -1) <= 0) {
				yyerror("invalid host %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			h = TAILQ_FIRST(&al);
			memcpy(&yyval.v.addr.ss, &h->ss, sizeof(yyval.v.addr.ss));
			host_free(&al);
		}
break;
case 210:
#line 1720 "parse.y"
{ yyval.v.number = 0; }
break;
case 211:
#line 1721 "parse.y"
{
			if ((yyval.v.number = yyvsp[0].v.number) < 0) {
				yyerror("invalid retry value: %d\n", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 212:
#line 1730 "parse.y"
{
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid timeout: %d\n", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.tv.tv_sec = yyvsp[0].v.number / 1000;
			yyval.v.tv.tv_usec = (yyvsp[0].v.number % 1000) * 1000;
		}
break;
#line 4050 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
