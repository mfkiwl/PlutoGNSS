################################################################################
#
# PlutoGNSS GNSS Timestamp TCP server
#
################################################################################

#PLUTOGNSS_VERSION = master
#PLUTOGNSS_SITE = git://github.com/Arribas/PlutoGNSS
#PLUTOGNSS_SITE_METHOD = git
PLUTOGNSS_SITE = /home/javier/git/PlutoGNSS
PLUTOGNSS_SITE_METHOD = local
#PLUTOGNSS_LICENSE = GPL-3
#PLUTOGNSS_LICENSE_FILES = LICENSE

#PLUTOGNSS_SOURCE = libfoo-$(LIBFOO_VERSION).tar.gz
#PLUTOGNSS_SITE = http://www.foosoftware.org/download
PLUTOGNSS_INSTALL_STAGING = YES
PLUTOGNSS_INSTALL_TARGET = NO
#PLUTOGNSS_CONF_OPTS = -DWITH_BOOST_STATIC=OFF -DWITH_SHARED_LIB=ON
PLUTOGNSS_DEPENDENCIES = libglib2 host-pkgconf boost

$(eval $(cmake-package))
