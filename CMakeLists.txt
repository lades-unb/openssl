# openssl module
# This module contains the customized source of OpenSSL.

# Make all includes relative to root dir
include_directories(
    include
    include/openssl
    crypto
    crypto/cmac
    crypto/modes
    crypto/evp
    crypto/des
    crypto/pqueue
    crypto/ecdsa
    crypto/ec
    crypto/engine
    crypto/bio
    crypto/pades
)

# Get the source files
file(GLOB FILES *.c */*.c */*/*.c */*/*/*.c)
set(SOURCES ${FILES})

# Remove files
list(FILTER SOURCES EXCLUDE REGEX LPdir_.*.c$)
list(FILTER SOURCES EXCLUDE REGEX armcap.c$)
list(FILTER SOURCES EXCLUDE REGEX .*test.*)
list(FILTER SOURCES EXCLUDE REGEX .*speed.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/rc2.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/rc2/tab.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/rc4.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/rc5.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/bf_opts.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/bfspeed.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/bss_rtcp.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/exp.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/cast_spd.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/castopts.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/cnf_save.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/des_opts.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/idea_spd.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/ppccap.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/s390xcap.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/sparcv9cap.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/v3conf.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/v3prin.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/sha1.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/sha.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/rmd160.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/aes_x86core.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/dh/p.*.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/sha/sha512t.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/sha/sha256t.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/bf_cbc.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/dsagen.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/md2.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/md4.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/md5.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/rpw.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/e_dsa.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/ecp_nistz.*.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/openbsd_hw.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/ecp_nistputil.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/ecp_nistp521.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/ecp_nistp256.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/ecp_nistp224.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/fips_ers.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/bn/asm/*)
list(FILTER SOURCES EXCLUDE REGEX .*/des/des.c$)
list(FILTER SOURCES EXCLUDE REGEX .*/des/ncbc_enc.c$)

# Output
add_library(openssl ${SOURCES})
