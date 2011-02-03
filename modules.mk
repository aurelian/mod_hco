mod_hco.la: mod_hco.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_hco.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_hco.la
