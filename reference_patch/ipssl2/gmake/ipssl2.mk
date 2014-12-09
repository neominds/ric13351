#############################################################################
#			      IPSSL.MK
#
#     Document no: @(#) $Name: release6_9_2 $ $RCSfile: ipssl2.mk,v $ $Revision: 1.9 $
#     $Source: /home/interpeak/CVSRoot/ipssl2/gmake/ipssl2.mk,v $
#     $Author: rboden $ $Date: 2010-03-15 13:20:14 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#
#############################################################################


#############################################################################
# PRODUCT
###########################################################################

IPPROD ?= ipssl



#############################################################################
# CONFIGURATION
###########################################################################

IPSSL_SRCROOT = $(IPSSL_ROOT)/openssl-0_9_8

#############################################################################
# DEFINE
###########################################################################

IPDEFINE += -DIPSSL


#############################################################################
# INCLUDE
###########################################################################

IPINCLUDE += -I$(IPSSL_ROOT)/config
IPINCLUDE += -I$(IPSSL_ROOT)/include
IPINCLUDE += -I$(IPSSL_SRCROOT)/include

IPLIBINCLUDE += -I$(IPXINC_ROOT)/include


#############################################################################
# OBJECTS
###########################################################################

# Configuration
IPLIBOBJECTS_C += ipssl_config.o

# Main
IPLIBOBJECTS += ipssl.o
IPLIBOBJECTS += bio_ssl.o
IPLIBOBJECTS += d1_both.o
IPLIBOBJECTS += d1_clnt.o
IPLIBOBJECTS += d1_enc.o
IPLIBOBJECTS += d1_lib.o
IPLIBOBJECTS += d1_meth.o
IPLIBOBJECTS += d1_pkt.o
IPLIBOBJECTS += d1_srvr.o
IPLIBOBJECTS += kssl.o
IPLIBOBJECTS += ocsp.o
IPLIBOBJECTS += s23_clnt.o
IPLIBOBJECTS += s23_lib.o
IPLIBOBJECTS += s23_meth.o
IPLIBOBJECTS += s23_pkt.o
IPLIBOBJECTS += s23_srvr.o
IPLIBOBJECTS += s2_clnt.o
IPLIBOBJECTS += s2_enc.o
IPLIBOBJECTS += s2_lib.o
IPLIBOBJECTS += s2_meth.o
IPLIBOBJECTS += s2_pkt.o
IPLIBOBJECTS += s2_srvr.o
IPLIBOBJECTS += s3_both.o
IPLIBOBJECTS += s3_cbc.o
IPLIBOBJECTS += s3_clnt.o
IPLIBOBJECTS += s3_enc.o
IPLIBOBJECTS += s3_lib.o
IPLIBOBJECTS += s3_meth.o
IPLIBOBJECTS += s3_pkt.o
IPLIBOBJECTS += s3_srvr.o
IPLIBOBJECTS += ssl_algs.o
IPLIBOBJECTS += ssl_asn1.o
IPLIBOBJECTS += ssl_cert.o
IPLIBOBJECTS += ssl_ciph.o
IPLIBOBJECTS += ssl_err.o
IPLIBOBJECTS += ssl_err2.o
IPLIBOBJECTS += ssl_lib.o
IPLIBOBJECTS += ssl_rsa.o
IPLIBOBJECTS += ssl_sess.o
IPLIBOBJECTS += ssl_stat.o
IPLIBOBJECTS += ssl_txt.o
IPLIBOBJECTS += ssltest.o
IPLIBOBJECTS += t1_clnt.o
IPLIBOBJECTS += t1_enc.o
IPLIBOBJECTS += t1_lib.o
IPLIBOBJECTS += t1_meth.o
IPLIBOBJECTS += t1_reneg.o
IPLIBOBJECTS += t1_srvr.o

# Shell commands
ifneq ($(IPPORT),itron)
IPLIBOBJECTS += s_client.o
IPLIBOBJECTS += s_server.o
endif
IPLIBOBJECTS += s_cb.o
IPLIBOBJECTS += s_socket.o
IPLIBOBJECTS += s_time.o
IPLIBOBJECTS += ciphers.o
IPLIBOBJECTS += ipssl_cmds.o
IPLIBOBJECTS += errstr.o

# Test shell commands
IPLIBOBJECTS += ssltest.o


# Compiles the xxx_config.o if the $SKIP_CONFIG macro is either not defined
# or set to anything other than true.
ifneq ($(SKIP_CONFIG),true)
IPLIBOBJECTS    += $(IPLIBOBJECTS_C)
endif

#############################################################################
# SOURCE
###########################################################################

IPSRCDIRS += $(IPSSL_ROOT)/src $(IPSSL_ROOT)/config
IPSRCDIRS += $(IPSSL_SRCROOT)/apps
IPSRCDIRS += $(IPSSL_SRCROOT)/ssl


#############################################################################
# LIB
###########################################################################

IPLIBS += $(IPLIBROOT)/libipssl.a


###########################################################################
# END OF IPSSL2.MK
###########################################################################
