/*
 ******************************************************************************
 *                     INTERPEAK SOURCE FILE
 *
 *   Document no: @(#) $Name: release6_9_2 $ $RCSfile: ipssl_cmds.c,v $ $Revision: 1.11 $
 *   $Source: /home/interpeak/CVSRoot/ipssl2/src/ipssl_cmds.c,v $
 *   $Author: rboden $
 *   $State: Exp $ $Locker:  $
 *
 *   INTERPEAK_COPYRIGHT_STRING
 *   Design and implementation by Roger Boden <roger@interpeak.se>
 ******************************************************************************
 */


/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 2                    CONFIGURATION
 ****************************************************************************
 */

#include "ipssl_config.h"


/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */
#define IPCOM_USE_CLIB_PROTO
#include <ipcom_type.h>
#include <ipcom_cstyle.h>
#include <ipcom_clib.h>
#include <ipcom_getopt.h>
#include <ipcom_sock.h>
#include <ipcom_sock2.h>
#include <ipcom_time.h>
#include <ipcom_err.h>
#include <ipcom_tmo.h>

#include <openssl/ssl.h>

/*
 ****************************************************************************
 * 4                    DEFINES
 ****************************************************************************
 */
#define IPSSL_CMD_BUF_SIZE 32*1024
#define IPSSL_CMD_PORT 5005
#define IPSSL_CMD_BUF_LEN 1440
#define IPSSL_CMD_TIME 3

/*
 ****************************************************************************
 * 5                    TYPES
 ****************************************************************************
 */
struct Ipssl_cmd_args_st
{
    int port;
    char* addr;
    int l;
    int n;
    int t;
    Ip_bool echo_data;
    char* key_file;
    char* cert_file;
    char* ciphers;
};
typedef struct Ipssl_cmd_args_st Ipssl_cmd_args;

/*
 ****************************************************************************
 * 6                    EXTERN PROTOTYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 7                    LOCAL PROTOTYPES
 ****************************************************************************
 */
IP_GLOBAL int ipssl_cmd_ssl_clt(int argc, char** argv);
IP_GLOBAL int ipssl_cmd_ssl_srv(int argc, char** argv);

/*
 ****************************************************************************
 * 8                    DATA
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 9                    STATIC FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                    ipssl_setup_ssl_ctx
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC Ip_err
ipssl_setup_ssl_ctx(SSL_CTX** ssl_ctx, const char* cert_file, const char* key_file, SSL_METHOD* ssl_method)
{
    *ssl_ctx = SSL_CTX_new(ssl_method);
    if(!*ssl_ctx)
    {
        ipcom_fprintf(ip_stderr, "SSL_CTX_new() failed"IP_LF);
        return IPCOM_ERR_FAILED;
    }
    if(!cert_file || !key_file)
        return IPCOM_SUCCESS;
    if(SSL_CTX_use_certificate_file(*ssl_ctx,cert_file, SSL_FILETYPE_PEM) != 1)
    {
        ipcom_fprintf(ip_stderr, "Failed to load cert file, %s"IP_LF, cert_file);
        return IPCOM_ERR_FAILED;
    }
    if(SSL_CTX_use_PrivateKey_file(*ssl_ctx,key_file, SSL_FILETYPE_PEM) != 1)
    {
        ipcom_fprintf(ip_stderr, "Failed to load key file, %s"IP_LF, key_file);
        return IPCOM_ERR_FAILED;
    }

    return IPCOM_SUCCESS;
}


/*
 *===========================================================================
 *                    ipssl_cmd_init_args
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipssl_cmd_init_args(Ipssl_cmd_args* args)
{
    ipcom_memset(args, 0, sizeof(Ipssl_cmd_args));

    args->port = IPSSL_CMD_PORT;
    args->l = IPSSL_CMD_BUF_LEN;
    args->n = 0;
    args->t = IPSSL_CMD_TIME;
}


/*
 *===========================================================================
 *                    ipssl_cmd_ssl_clt_usage
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipssl_cmd_ssl_clt_usage(void)
{
    ipcom_printf("ssl_clt [options] "IP_LF
                 "options:"IP_LF
                 "  -a <addr>    addr to connect to"IP_LF
                 "  -p <port>    port to use (default %d)"IP_LF
                 "  -e           echo data"IP_LF
                 "  -l <len>     length of buffers (default %d)"IP_LF
                 "  -n <no>      no of buffers (cannot be used with -t)"IP_LF
                 "  -t <sec>     no of seconds to run (default %d, cannot be used with -n)"IP_LF
                 "  -k <file>    key file"IP_LF
                 "  -x <file>    X509 certificate file"IP_LF
                 "  -c <ciphers> SSL cipher suites to use"IP_LF
                 "  -h           print usage info"IP_LF, IPSSL_CMD_PORT, IPSSL_CMD_BUF_LEN, IPSSL_CMD_TIME);
}

/*
 *===========================================================================
 *                    ipssl_cmd_ssl_srv_usage
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipssl_cmd_ssl_srv_usage(void)
{
    ipcom_printf("ssl_srv [options] "IP_LF
                 "options:"IP_LF
                 "  -p <port> port to use (default %d)"IP_LF
                 "  -e        echo data"IP_LF
                 "  -k <file> key file"IP_LF
                 "  -x <file> X509 certificate file"IP_LF
                 "  -h        print usage info"IP_LF, IPSSL_CMD_PORT);
}


/*
 *===========================================================================
 *                    ipssl_cmd_parse_args
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC Ip_err
ipssl_cmd_parse_args(int argc, char** argv, Ipssl_cmd_args* args)
{
    Ipcom_getopt opt;
    int c;

    ipcom_getopt_clear_r(&opt);
    while((c=ipcom_getopt_r(argc, argv, "a:p:el:n:k:x:c:ht:", &opt)) != -1)
    {
        switch(c)
        {
        case 'a':
            args->addr = opt.optarg;
            break;
        case 'p':
            args->port = ipcom_atoi(opt.optarg);
            break;
        case 'e':
            args->echo_data = IP_TRUE;
            break;
        case 'l':
            args->l = ipcom_atoi(opt.optarg);
            break;
        case 'n':
            args->n = ipcom_atoi(opt.optarg);
            args->t = 0;
            break;
        case 'k':
            args->key_file = opt.optarg;
            break;
        case 'x':
            args->cert_file = opt.optarg;
            break;
        case 'h':
            return IPCOM_ERR_FAILED;
        case 'c':
            args->ciphers = opt.optarg;
            break;
        case 't':
            args->t = ipcom_atoi(opt.optarg);
            args->n = 0;
            break;
        default:
            return IPCOM_ERR_FAILED;
        }
    }

    return IPCOM_SUCCESS;
}

/*
 *===========================================================================
 *                    ipssl_get_elapsed_msecs
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC int
ipssl_get_elapsed_msecs(struct Ip_timeval* start_time, struct Ip_timeval* stop_time)
{
    int milli_sec;

    milli_sec = 1000*(stop_time->tv_sec - start_time->tv_sec);
    milli_sec += (stop_time->tv_usec - start_time->tv_usec)/1000;

    return milli_sec;
}

/*
 ****************************************************************************
 * 10                   GLOBAL FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                    ipssl_cmd_ssl_clt
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_GLOBAL int
ipssl_cmd_ssl_clt(int argc, char** argv)
{
    union Ip_sockaddr_union addr;
    struct Ip_addrinfo* addrinfo = IP_NULL;
    Ip_fd sock = IP_INVALID_SOCKET;
    Ipssl_cmd_args cmd_args;
    int rc = IPCOM_ERR_FAILED;
    char* buf = IP_NULL;
    int i;
    int ret_val;
    struct Ip_timeval start_time;
    struct Ip_timeval stop_time;
    int msec;

    SSL_CTX* ssl_ctx = IP_NULL;
    SSL* ssl = IP_NULL;

    ipssl_cmd_init_args(&cmd_args);
    if(argc == 1 || ipssl_cmd_parse_args(argc, argv, &cmd_args) != IPCOM_SUCCESS)
    {
        ipssl_cmd_ssl_clt_usage();
        return IPCOM_ERR_FAILED;
    }
    if(!cmd_args.addr)
    {
        ipcom_fprintf(ip_stderr, "No addr specified. Use -a"IP_LF);
        return IPCOM_ERR_FAILED;
    }

    if(ipssl_setup_ssl_ctx(&ssl_ctx, cmd_args.cert_file, cmd_args.key_file, SSLv23_client_method()) != IPCOM_SUCCESS)
        goto cleanup;
    if(cmd_args.ciphers)
    {
		if(!SSL_CTX_set_cipher_list(ssl_ctx,cmd_args.ciphers))
        {
            ipcom_fprintf(ip_stderr, "Failed to set cipher : %s"IP_LF, cmd_args.ciphers);
            goto cleanup;
        }
    }
    ipcom_memset(&addr, 0, sizeof(addr));
    if(ipcom_getaddrinfo(cmd_args.addr, IP_NULL, IP_NULL, &addrinfo) != IPCOM_SUCCESS)
    {
        ipcom_fprintf(ip_stderr, "bad addr argument: %s"IP_LF, cmd_args.addr);
        goto cleanup;
    }
    ipcom_memcpy(&addr.sa, addrinfo->ai_addr, addrinfo->ai_addrlen);
    addr.sin.sin_port = (Ip_in_port_t)ip_htons(cmd_args.port);

    sock = ipcom_socket(addrinfo->ai_family, IP_SOCK_STREAM, 0);
    if(sock == IP_INVALID_SOCKET)
    {
        ipcom_fprintf(ip_stderr, "ipcom_socket() failed: errno=%d"IP_LF, ipcom_errno);
        goto cleanup;
    }

    if(ipcom_connect(sock, &addr.sa, IPCOM_SA_LEN_GET(&addr.sa)) != IPCOM_SUCCESS)
    {
        ipcom_fprintf(ip_stderr, "ipcom_connect() failed: errno=%d"IP_LF, ipcom_errno);
        goto cleanup;
    }

    ssl = SSL_new(ssl_ctx);
    if(!ssl)
    {
        ipcom_fprintf(ip_stderr, "SSL_new() failed"IP_LF);
        goto cleanup;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);
    if(SSL_do_handshake(ssl) != 1)
    {
        ipcom_fprintf(ip_stderr, "SSL_do_handshake() failed"IP_LF);
        goto cleanup;
    }

    buf = ipcom_malloc(cmd_args.l);
    if(!buf)
    {
        ipcom_fprintf(ip_stderr, "Out of memory"IP_LF);
        goto cleanup;
    }

    if(cmd_args.t > 0)
    {
        if (0 != ipcom_socketioctl(sock, IP_X_SIOCSINTR, &(cmd_args.t) ) )
        {
            ipcom_printf("ipcom_socketioctl(IP_X_SIOCSINTR) failed: %s"IP_LF,
                         ipcom_strerror(ipcom_errno));
            goto cleanup;
        }
    }
    ipcom_microtime(&start_time);

    for(i=0;cmd_args.t>0 || (cmd_args.n>0 && i<cmd_args.n);i++)
    {
        ret_val = SSL_write(ssl, buf, cmd_args.l);
        if(ret_val != cmd_args.l)
        {
            if (ipcom_errno == IP_ERRNO_EINTR)
                break;

            ipcom_fprintf(ip_stderr, "SSL_write() failed, i=%d"IP_LF, i);
            goto cleanup;
        }
        if(cmd_args.echo_data)
        {
            ret_val = SSL_read(ssl, buf, cmd_args.l);
            if(ret_val != cmd_args.l)
            {
                if (ipcom_errno == IP_ERRNO_EINTR)
                    break;
                ipcom_fprintf(ip_stderr, "SSL_read() failed, i=%d"IP_LF, i);
                goto cleanup;
            }
        }
    }
    ipcom_microtime(&stop_time);
    msec = ipssl_get_elapsed_msecs(&start_time, &stop_time);
    if (msec > 0 && i > 0)
    {
        if(cmd_args.echo_data)
        {
            ipcom_fprintf(ip_stderr, "Echoed  %d pkt/sec, %d Kbytes/sec (%d bytes (%d*%d) in %d msecs),"IP_LF,
                          i*1000/msec, cmd_args.l*i/msec*1000/1024,
                          cmd_args.l*i, cmd_args.l, i, msec);
        }
        else
        {
            ipcom_fprintf(ip_stderr, "Wrote  %d pkt/sec, %d Kbytes/sec (%d bytes (%d*%d) in %d msecs),"IP_LF,
                          i*1000/msec, cmd_args.l*i/msec*1000/1024,
                          cmd_args.l*i, cmd_args.l, i, msec);
        }
    }
    else
    {
        ipcom_printf("Failed, too short measurement time (< 1 msec)");
        rc = IPCOM_ERR_FAILED;
    }

    rc = IPCOM_SUCCESS;

 cleanup:
    if(sock != IP_INVALID_SOCKET)
        ipcom_socketclose(sock);
    if(addrinfo)
        ipcom_freeaddrinfo(addrinfo);
    if(ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    if(ssl)
        SSL_free(ssl);
    if(buf)
        ipcom_free(buf);

    return rc;
}

/*
 *===========================================================================
 *                    ipssl_cmd_ssl_srv
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_GLOBAL int
ipssl_cmd_ssl_srv(int argc, char** argv)
{
    union Ip_sockaddr_union addr;
    Ip_fd sock = IP_INVALID_SOCKET;
    Ip_fd sock2 = IP_INVALID_SOCKET;
    Ipssl_cmd_args cmd_args;
    int rc = IPCOM_ERR_FAILED;
    char* buf = IP_NULL;
    int i;
    int ret_val;
    int on = 1;
    int sess_id = 4711;

    SSL_CTX* ssl_ctx = IP_NULL;
    SSL* ssl = IP_NULL;

    ipssl_cmd_init_args(&cmd_args);
    if(argc == 1 || ipssl_cmd_parse_args(argc, argv, &cmd_args) != IPCOM_SUCCESS)
    {
        ipssl_cmd_ssl_srv_usage();
        return IPCOM_ERR_FAILED;
    }
    if(!cmd_args.key_file || !cmd_args.cert_file)
    {
        ipcom_fprintf(ip_stderr, "Key and certificate files must be specified"IP_LF);
        goto cleanup;
    }
    if(ipssl_setup_ssl_ctx(&ssl_ctx, cmd_args.cert_file, cmd_args.key_file, SSLv23_server_method()) != IPCOM_SUCCESS)
        goto cleanup;
    SSL_CTX_set_session_id_context(ssl_ctx, (unsigned char*) &sess_id, sizeof(sess_id));

    ipcom_memset(&addr, 0, sizeof(addr));
    addr.sin.sin_port = (Ip_in_port_t)ip_htons(cmd_args.port);
#ifdef IPCOM_USE_INET6
    addr.sa.sa_family = IP_AF_INET6;
    IPCOM_SA_LEN_SET(&addr.sa, sizeof(struct Ip_sockaddr_in6));
#else
    addr.sa.sa_family = IP_AF_INET;
    IPCOM_SA_LEN_SET(&addr.sa, sizeof(struct Ip_sockaddr_in));
#endif
    sock = ipcom_socket(addr.sa.sa_family, IP_SOCK_STREAM, 0);
    if(sock == IP_INVALID_SOCKET)
    {
        ipcom_fprintf(ip_stderr, "ipcom_socket() failed: errno=%d"IP_LF, ipcom_errno);
        goto cleanup;
    }
    if( ipcom_setsockopt(sock, IP_SOL_SOCKET, IP_SO_REUSEADDR, (void*) &on, sizeof(on)) )
    {
        ipcom_fprintf(ip_stderr, "ipcom_setsockopt(IP_SO_REUSEADDR) failed, error=%d", ipcom_errno);
        goto cleanup;
    }
    if(ipcom_bind(sock, &addr.sa, IPCOM_SA_LEN_GET(&addr.sa)) != IPCOM_SUCCESS)
    {
        ipcom_fprintf(ip_stderr, "ipcom_bind() failed: errno=%d"IP_LF, ipcom_errno);
        goto cleanup;
    }
    if(ipcom_listen(sock, 5) != IPCOM_SUCCESS)
    {
        ipcom_fprintf(ip_stderr, "ipcom_listen() failed: errno=%d"IP_LF, ipcom_errno);
        goto cleanup;
    }

    ssl = SSL_new(ssl_ctx);
    if(!ssl)
    {
        ipcom_fprintf(ip_stderr, "SSL_new() failed"IP_LF);
        goto cleanup;
    }

    ipcom_fprintf(ip_stderr, "accept:"IP_LF);
    sock2 = ipcom_accept(sock, IP_NULL, IP_NULL);
    buf = ipcom_malloc(IPSSL_CMD_BUF_SIZE);
    if(!buf)
    {
        ipcom_fprintf(ip_stderr, "Out of memory"IP_LF);
        goto cleanup;
    }

    if(sock2 == IP_INVALID_SOCKET)
    {
        ipcom_fprintf(ip_stderr, "ipcom_accept() failed, errno=%d"IP_LF, ipcom_errno);
        goto cleanup;
    }
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, sock2);
    if(SSL_do_handshake(ssl) != 1)
    {
        ipcom_fprintf(ip_stderr, "SSL_do_handshake() failed"IP_LF);
        goto cleanup;
    }

    i=0;
    for(;;)
    {
        ret_val = SSL_read(ssl, buf, IPSSL_CMD_BUF_SIZE);
        if(ret_val == 0)
            break;

        if(ret_val < 0)
        {
            ipcom_fprintf(ip_stderr, "SSL_read() failed, i=%d, errno=%d"IP_LF, i, ipcom_errno);
            goto cleanup;
        }
        if(cmd_args.echo_data)
        {
            if(SSL_write(ssl, buf, ret_val) != ret_val)
            {
                ipcom_fprintf(ip_stderr, "SSL_write() failed, i=%d"IP_LF, i);
                goto cleanup;
            }
        }
        i++;
    }

    rc = IPCOM_SUCCESS;

 cleanup:
    if(sock != IP_INVALID_SOCKET)
        ipcom_socketclose(sock);
    if(sock2 != IP_INVALID_SOCKET)
        ipcom_socketclose(sock2);
    if(ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    if(ssl)
        SSL_free(ssl);
    if(buf)
        ipcom_free(buf);

    return rc;
}


/*
 ****************************************************************************
 * 11                   PUBLIC FUNCTIONS
 ****************************************************************************
 */

/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */

