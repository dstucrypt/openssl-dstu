DIR=uadstu
TOP=../..
CC=cc
INCLUDES= -I../../include
CFLAG=-g
MAKEFILE= Makefile
AR= ar r
CFLAGS= $(INCLUDES) $(CFLAG)
LIB=$(TOP)/libcrypto.a

TEST=dstutest.c

LIBSRC= dstu_ameth.c dstu_asn1.c dstu_cipher.c dstu_compress.c dstu_engine.c dstu_key.c dstu_md.c dstu_params.c dstu_pmeth.c dstu_sign.c dstu89.c dstuhash.c dstu_rbg.c

LIBOBJ= e_dstu_err.o dstu_ameth.o dstu_asn1.o dstu_cipher.o dstu_compress.o dstu_engine.o dstu_key.o dstu_md.o dstu_params.o dstu_pmeth.o dstu_sign.o dstu89.o dstuhash.o dstu_rbg.o

SRC=$(LIBSRC)

LIBNAME=dstu

top: 
	(cd $(TOP); $(MAKE) DIRS=engines EDIRS=$(DIR) sub_all)

all: lib

tags:
	ctags $(SRC)

errors:
	$(PERL) ../../util/mkerr.pl -conf dstu.ec -nostatic -write $(SRC)

lib: $(LIBOBJ)
	if [ -n "$(SHARED_LIBS)" ]; then \
		$(MAKE) -f $(TOP)/Makefile.shared -e \
			LIBNAME=$(LIBNAME) \
			LIBEXTRAS='$(LIBOBJ)' \
			LIBDEPS='-L$(TOP) -lcrypto' \
			link_o.$(SHLIB_TARGET); \
	else \
		$(AR) $(LIB) $(LIBOBJ); \
	fi
	@touch lib

install:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(LIBNAME); \
		pfx=lib; \
		if [ "$(PLATFORM)" != "Cygwin" ]; then \
			case "$(CFLAGS)" in \
			*DSO_BEOS*) sfx=".so";; \
			*DSO_DLFCN*) sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;; \
			*DSO_DL*) sfx=".sl";; \
			*DSO_WIN32*) sfx="eay32.dll"; pfx=;; \
			*) sfx=".bad";; \
			esac; \
			cp $${pfx}$(LIBNAME)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		else \
			sfx=".so"; \
			cp cyg$(LIBNAME).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		fi; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx; \
	fi

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)

tests:

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC); \
	fi

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll *.dylib

# DO NOT DELETE THIS LINE -- make depend depends on it.

dstu89.o: ../ccgost/gost89.c ../ccgost/gost89.h dstu89.c
dstu_ameth.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
dstu_ameth.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dstu_ameth.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_ameth.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
dstu_ameth.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
dstu_ameth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dstu_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dstu_ameth.o: ../../include/openssl/objects.h
dstu_ameth.o: ../../include/openssl/opensslconf.h
dstu_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_ameth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dstu_ameth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dstu_ameth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
dstu_ameth.o: ../../include/openssl/x509_vfy.h ../ccgost/gost89.h dstu_ameth.c
dstu_ameth.o: dstu_asn1.h dstu_compress.h dstu_engine.h dstu_key.h
dstu_ameth.o: dstu_params.h e_dstu_err.h
dstu_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
dstu_asn1.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dstu_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_asn1.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
dstu_asn1.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
dstu_asn1.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dstu_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dstu_asn1.o: ../../include/openssl/objects.h
dstu_asn1.o: ../../include/openssl/opensslconf.h
dstu_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dstu_asn1.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dstu_asn1.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
dstu_asn1.o: ../../include/openssl/x509_vfy.h dstu_asn1.c dstu_asn1.h
dstu_asn1.o: dstu_engine.h
dstu_cipher.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dstu_cipher.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dstu_cipher.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dstu_cipher.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
dstu_cipher.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dstu_cipher.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dstu_cipher.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dstu_cipher.o: ../../include/openssl/opensslconf.h
dstu_cipher.o: ../../include/openssl/opensslv.h
dstu_cipher.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
dstu_cipher.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dstu_cipher.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dstu_cipher.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dstu_cipher.o: ../ccgost/gost89.h dstu_cipher.c dstu_engine.h dstu_params.h
dstu_compress.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dstu_compress.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_compress.o: ../../include/openssl/ec.h ../../include/openssl/opensslconf.h
dstu_compress.o: ../../include/openssl/opensslv.h
dstu_compress.o: ../../include/openssl/ossl_typ.h
dstu_compress.o: ../../include/openssl/safestack.h
dstu_compress.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dstu_compress.o: ../ccgost/gost89.h dstu_compress.c dstu_compress.h
dstu_compress.o: dstu_params.h
dstu_engine.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dstu_engine.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dstu_engine.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dstu_engine.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
dstu_engine.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dstu_engine.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dstu_engine.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dstu_engine.o: ../../include/openssl/opensslconf.h
dstu_engine.o: ../../include/openssl/opensslv.h
dstu_engine.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
dstu_engine.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dstu_engine.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dstu_engine.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dstu_engine.o: ../ccgost/gost89.h dstu_engine.c dstu_engine.h dstu_params.h
dstu_engine.o: e_dstu_err.h
dstu_key.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
dstu_key.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
dstu_key.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dstu_key.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dstu_key.o: ../../include/openssl/opensslconf.h
dstu_key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dstu_key.o: ../../include/openssl/symhacks.h ../ccgost/gost89.h dstu_asn1.h
dstu_key.o: dstu_compress.h dstu_key.c dstu_key.h dstu_params.h
dstu_md.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
dstu_md.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dstu_md.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_md.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
dstu_md.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
dstu_md.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dstu_md.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dstu_md.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
dstu_md.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_md.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dstu_md.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dstu_md.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
dstu_md.o: ../../include/openssl/x509_vfy.h ../ccgost/gost89.h
dstu_md.o: ../ccgost/gosthash.h dstu_asn1.h dstu_engine.h dstu_key.h dstu_md.c
dstu_md.o: dstu_params.h
dstu_params.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dstu_params.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_params.o: ../../include/openssl/ec.h ../../include/openssl/evp.h
dstu_params.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dstu_params.o: ../../include/openssl/opensslconf.h
dstu_params.o: ../../include/openssl/opensslv.h
dstu_params.o: ../../include/openssl/ossl_typ.h
dstu_params.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dstu_params.o: ../../include/openssl/symhacks.h ../ccgost/gost89.h
dstu_params.o: dstu_params.c dstu_params.h
dstu_pmeth.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
dstu_pmeth.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dstu_pmeth.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_pmeth.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
dstu_pmeth.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
dstu_pmeth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dstu_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dstu_pmeth.o: ../../include/openssl/objects.h
dstu_pmeth.o: ../../include/openssl/opensslconf.h
dstu_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dstu_pmeth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dstu_pmeth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
dstu_pmeth.o: ../../include/openssl/x509_vfy.h ../ccgost/gost89.h dstu_asn1.h
dstu_pmeth.o: dstu_engine.h dstu_key.h dstu_params.h dstu_pmeth.c e_dstu_err.h
dstu_rbg.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dstu_rbg.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dstu_rbg.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dstu_rbg.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
dstu_rbg.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dstu_rbg.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dstu_rbg.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dstu_rbg.o: ../../include/openssl/opensslconf.h
dstu_rbg.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_rbg.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dstu_rbg.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dstu_rbg.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
dstu_rbg.o: ../../include/openssl/x509_vfy.h ../ccgost/gost89.h dstu_engine.h
dstu_rbg.o: dstu_params.h dstu_rbg.c
dstu_sign.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dstu_sign.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dstu_sign.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
dstu_sign.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
dstu_sign.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
dstu_sign.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dstu_sign.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dstu_sign.o: ../../include/openssl/objects.h
dstu_sign.o: ../../include/openssl/opensslconf.h
dstu_sign.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dstu_sign.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dstu_sign.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dstu_sign.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
dstu_sign.o: ../../include/openssl/x509_vfy.h ../ccgost/gost89.h dstu_engine.h
dstu_sign.o: dstu_params.h dstu_sign.c e_dstu_err.h
dstuhash.o: ../ccgost/gost89.h ../ccgost/gosthash.c ../ccgost/gosthash.h
dstuhash.o: dstuhash.c
