/*
 ******************************************************************************
 *                     INTERPEAK CONFIGURATION SOURCE FILE
 *
 *   Document no: @(#) $Name: release6_9_2 $ $RCSfile: ipssl_config.c,v $ $Revision: 1.10 $
 *   $Source: /home/interpeak/CVSRoot/ipssl2/config/ipssl_config.c,v $
 *   $Author: rboden $
 *   $State: Exp $ $Locker:  $
 *
 *   Copyright Interpeak AB 2000-2003 <www.interpeak.se>. All rights reserved.
 *     Design and implementation by Roger Boden <roger@interpeak.se>
 ******************************************************************************
 */


/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 2                    INCLUDE FILES
 ****************************************************************************
 */

#include "ipssl.h"
#include "ipssl_config.h"

#include <ipcom_type.h>
#include <ipcom_cstyle.h>
#include <ipcom_shell.h>
#include <ipcom_os.h>
#include <ipcom_err.h>

/*
 ****************************************************************************
 * 3                    DEFINES
 ****************************************************************************
 */

#ifdef PRJ_BUILD

#ifdef IPSSL_USE_TEST_CMDS
#undef IPSSL_USE_TEST_CMDS
#endif
#ifdef INCLUDE_IPSSL_USE_TEST_CMDS
#define IPSSL_USE_TEST_CMDS
#endif

#endif /* PRJ_BUILD */

#if defined(IPSSL_USE_CMDS) && !defined(IP_PORT_VXWORKS) || defined(INCLUDE_IPSSL_USE_CMDS)

/*
 *===========================================================================
 *                    IPSSL_USE_CIPHERS_CMD
 *===========================================================================
 * Define to include the ciphers shell command
 */
#ifndef IP_PORT_LAS
#define IPSSL_USE_CIPHERS_CMD
#endif

/*
 *===========================================================================
 *                    IPSSL_USE_S_CLIENT_CMD
 *===========================================================================
 * Define to include the s_client shell command
 */
#if !defined(IP_PORT_ITRON) && !defined(IP_PORT_LAS)
#define IPSSL_USE_S_CLIENT_CMD
#endif

/*
 *===========================================================================
 *                    IPSSL_USE_S_SERVER_CMD
 *===========================================================================
 * Define to include the s_server shell command
 */
#if !defined(IP_PORT_ITRON) && !defined(IP_PORT_LAS)
#define IPSSL_USE_S_SERVER_CMD
#endif

/*
 *===========================================================================
 *                    IPSSL_USE_S_TIME_CMD
 *===========================================================================
 * Define to include the s_time shell command
 */
#ifndef IP_PORT_LAS
#define IPSSL_USE_S_TIME_CMD
#endif

/*
 *===========================================================================
 *                    IPSSL_USE_SSL_SRV_CMD
 *===========================================================================
 * Define to include the ssl_srv shell command
 */
#ifndef IP_PORT_LAS
#define IPSSL_USE_SSL_SRV_CMD
#endif

/*
 *===========================================================================
 *                    IPSSL_USE_SSL_CLT_CMD
 *===========================================================================
 * Define to include the ssl_clt shell command
 */
#ifndef IP_PORT_LAS
#define IPSSL_USE_SSL_CLT_CMD
#endif

#endif /* IPSSL_USE_CMDS */


/*
 ****************************************************************************
 * 4                    TYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 5                    EXTERN PROTOTYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 6                    LOCAL PROTOTYPES
 ****************************************************************************
 */
#ifdef IPSSL_USE_CMDS
IP_PUBLIC void ipcrypto_cmds_startup(void);
#ifdef IPSSL_USE_CIPHERS_CMD
IP_PUBLIC int ciphers_main(int argc, char** argv);
#endif
#ifdef IPSSL_USE_S_CLIENT_CMD
IP_PUBLIC int s_client_main(int argc, char** argv);
#endif
#ifdef IPSSL_USE_S_SERVER_CMD
IP_PUBLIC int s_server_main(int argc, char** argv);
#endif
#ifdef IPSSL_USE_S_TIME_CMD
IP_PUBLIC int s_time_main(int argc, char** argv);
#endif
#endif

IP_PUBLIC Ip_err ipssl_configure(void);

/*
 ****************************************************************************
 * 7                    DATA
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 8                    STATIC FUNCTIONS
 ****************************************************************************
 */

#ifdef IPSSL_USE_CIPHERS_CMD
IP_GLOBAL int
ipssl_ciphers(int argc, char** argv)
{
    ipcrypto_cmds_startup();
    return ciphers_main(argc, argv);
}
#endif

#ifdef IPSSL_USE_S_TIME_CMD
IP_GLOBAL int
ipssl_s_time(int argc, char** argv)
{
    ipcrypto_cmds_startup();
    return s_time_main(argc, argv);
}
#endif

#ifdef IPSSL_USE_S_CLIENT_CMD
IP_GLOBAL int
ipssl_s_client(int argc, char** argv)
{
    ipcrypto_cmds_startup();
    return s_client_main(argc, argv);
}
#endif

#ifdef IPSSL_USE_S_SERVER_CMD
IP_GLOBAL int
ipssl_s_server(int argc, char** argv)
{
    ipcrypto_cmds_startup();
    return s_server_main(argc, argv);
}
#endif

/*
 ****************************************************************************
 * 9                   GLOBAL FUNCTIONS
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 10                   PUBLIC FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                    ipssl_configure
 *===========================================================================
 */
IP_PUBLIC Ip_err
ipssl_configure(void)
{
#ifdef IPSSL_USE_CIPHERS_CMD
    ipcom_shell_add_cmd("ciphers", "ciphers", "SSL Cipher Suites", ipssl_ciphers,
                        IPCOM_PRIORITY_DEFAULT, IPCOM_PROC_STACK_MAX);
#endif
#ifdef IPSSL_USE_S_CLIENT_CMD
    ipcom_shell_add_cmd("s_client", "s_client", "SSL client", ipssl_s_client,
                        IPCOM_PRIORITY_DEFAULT, IPCOM_PROC_STACK_MAX);
#endif
#ifdef IPSSL_USE_S_SERVER_CMD
    ipcom_shell_add_cmd("s_server", "s_server", "SSL server", ipssl_s_server,
                        IPCOM_PRIORITY_DEFAULT, IPCOM_PROC_STACK_MAX);
#endif
#ifdef IPSSL_USE_S_TIME_CMD
    ipcom_shell_add_cmd("s_time", "s_time", "Time SSL connection", ipssl_s_time,
                        IPCOM_PRIORITY_DEFAULT, IPCOM_PROC_STACK_MAX);
#endif

#ifdef IPSSL_USE_SSL_CLT_CMD
    ipcom_shell_add_cmd("ssl_clt", "ssl_clt", "SSL client for performance measurements ", ipssl_cmd_ssl_clt,
                        IPCOM_PRIORITY_DEFAULT, IPCOM_PROC_STACK_MAX);
#endif
#ifdef IPSSL_USE_SSL_SRV_CMD
    ipcom_shell_add_cmd("ssl_srv", "ssl_srv", "SSL server for performance measurements ", ipssl_cmd_ssl_srv,
                        IPCOM_PRIORITY_DEFAULT, IPCOM_PROC_STACK_MAX);
#endif

#ifdef IPSSL_USE_TEST_CMDS
    ipcom_shell_add_cmd("ssltest", "ssltest", "ssltest", ssltest_main,
                        IPCOM_PRIORITY_DEFAULT, (64*1024-1));
#endif

    return IPCOM_SUCCESS;
}


/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */

