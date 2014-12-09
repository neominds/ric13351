/* 02comp_ipnet_ssl.cdf - IPSSL configuration file */

/*
 * Copyright (c) 2007 Wind River Systems, Inc.
 *
 * The right to copy, distribute or otherwise make use of this software
 * may be licensed only pursuant to the terms of an applicable Wind River
 * license agreement. No license to Wind River intellectual property rights
 * is granted herein. All rights not licensed by Wind River are reserved
 * by Wind River.
 */

/*
modification history
--------------------
01a,10sep07,mze re-added missing LINK_SYMS
*/

Folder FOLDER_SSL
{
    NAME            SSL Components
    SYNOPSIS        SSL Components
    DEFAULTS        INCLUDE_IPSSL
}

Component INCLUDE_IPSSL
        {
        NAME            SSL
        _CHILDREN       FOLDER_SSL
        SYNOPSIS        SSL Library
        CONFIGLETTES    ipssl_config.c
        MODULES         ipssl.o
        REQUIRES        INCLUDE_IPCRYPTO
        }

Component INCLUDE_IPSSL_USE_CMDS
        {
        NAME            SSL Cmds
        _CHILDREN       FOLDER_SSL
        SYNOPSIS        SSL Cmds
        LINK_SYMS       ipssl_cmd_ssl_srv \
                        ipssl_cmd_ssl_clt \
                        s_time_main \
                        s_server_main \
                        s_client_main
        REQUIRES        INCLUDE_IPSSL
        }

Component INCLUDE_IPSSL_USE_TEST_CMDS
        {
        NAME            SSL Test Cmds
        _CHILDREN       FOLDER_SSL
        SYNOPSIS        SSL Test Cmds
        LINK_SYMS       ssltest_main
        REQUIRES        INCLUDE_IPSSL
        }


