@echo off        

echo backing up Older files...

ren %1\vxworks-6.1\target\src\ssl\ssl\s2_lib.c s2_lib_b4ric13351.c 
ren %1\vxworks-6.1\target\src\ssl\ssl\s3_lib.c s3_lib_b4ric13351.c 
ren %1\vxworks-6.1\target\src\ssl\ssl\s3_enc.c s3_enc_b4ric13351.c 
ren %1\vxworks-6.1\target\src\ssl\ssl\ssl_lib.c ssl_lib_b4ric13351.c 
ren %1\vxworks-6.1\target\src\ssl\ssl\t1_enc.c t1_enc_b4ric13351.c 
ren %1\vxworks-6.1\target\src\ssl\ssl\ssl_err.c ssl_err_b4ric13351.c 


ren %1\vxworks-6.1\target\h\openssl\ssl.h ssl_b4ric13351.h
ren %1\vxworks-6.1\target\h\openssl\ssl3.h ssl3_b4ric13351.h
ren %1\vxworks-6.1\target\h\openssl\tls1.h tls1_b4ric13351.h 
 
echo copying RIC13351 patch files...

copy .\RIC13351\src\vxworks-6.1\target\src\ssl\ssl\s2_lib.c %1\vxworks-6.1\target\src\ssl\ssl\s2_lib.c 
copy .\RIC13351\src\vxworks-6.1\target\src\ssl\ssl\s3_lib.c %1\vxworks-6.1\target\src\ssl\ssl\s3_lib.c 
copy .\RIC13351\src\vxworks-6.1\target\src\ssl\ssl\s3_enc.c %1\vxworks-6.1\target\src\ssl\ssl\s3_enc.c 
copy .\RIC13351\src\vxworks-6.1\target\src\ssl\ssl\ssl_lib.c %1\vxworks-6.1\target\src\ssl\ssl\ssl_lib.c 
copy .\RIC13351\src\vxworks-6.1\target\src\ssl\ssl\t1_enc.c %1\vxworks-6.1\target\src\ssl\ssl\t1_enc.c 
copy .\RIC13351\src\vxworks-6.1\target\src\ssl\ssl\ssl_err.c %1\vxworks-6.1\target\src\ssl\ssl\ssl_err.c 

copy .\RIC13351\src\vxworks-6.1\target\h\openssl\ssl.h %1\vxworks-6.1\target\h\openssl\ssl.h 
copy .\RIC13351\src\vxworks-6.1\target\h\openssl\ssl3.h %1\vxworks-6.1\target\h\openssl\ssl3.h 
copy .\RIC13351\src\vxworks-6.1\target\h\openssl\tls1.h %1\vxworks-6.1\target\h\openssl\tls1.h 

if "%2" == "withtest" (

echo backing up older files...

ren %1\vxworks-6.1\target\src\ssl\ssl\apps\progs.h progs_b4ric13351.h
ren %1\vxworks-6.1\target\src\ssl\ssl\apps\Makefile Makefile_b4ric13351
ren %1\vxworks-6.1\target\src\ssl\ssl\apps\Makefile.ssl Makefile_b4ric13351.ssl
ren %1\vxworks-6.1\target\src\ssl\ssl\apps\Makefile.windriver Makefile_b4ric13351.windriver
ren %1\vxworks-6.1\target\src\ssl\ssl\apps\ssl_apps_link_syms.c ssl_apps_link_syms_b4ric13351.c

copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\nm_client.c %1\vxworks-6.1\target\src\ssl\ssl\apps\nm_client.c
copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\nm_server.c %1\vxworks-6.1\target\src\ssl\ssl\apps\nm_server.c
copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\ssl_apps_link_syms.c %1\vxworks-6.1\target\src\ssl\ssl\apps\ssl_apps_link_syms.c
copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\progs.h %1\vxworks-6.1\target\src\ssl\ssl\apps\progs.h
copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\Makefile %1\vxworks-6.1\target\src\ssl\ssl\apps\Makefile
copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\Makefile.ssl %1\vxworks-6.1\target\src\ssl\ssl\apps\Makefile.ssl
copy .\RIC13351\test_src\vxworks-6.1\target\src\ssl\ssl\apps\Makefile.windriver %1\vxworks-6.1\target\src\ssl\ssl\apps\Makefile.windriver

echo done

)

echo done.