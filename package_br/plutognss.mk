################################################################################
#
# PlutoGNSS GNSS Timestamp TCP server
#
################################################################################

PLUTOGNSS_VERSION = 1.0
PLUTOGNSS_SITE = https://github.com/Arribas/PlutoGNSS
PLUTOGNSS_SITE_METHOD = git
PLUTOGNSS_LICENSE = GPL-3
PLUTOGNSS_LICENSE_FILES = LICENSE

#PLUTOGNSS_SOURCE = libfoo-$(LIBFOO_VERSION).tar.gz
#PLUTOGNSS_SITE = http://www.foosoftware.org/download
PLUTOGNSS_INSTALL_STAGING = YES
PLUTOGNSS_INSTALL_TARGET = NO
#PLUTOGNSS_CONF_OPTS = -DBUILD_DEMOS=ON
PLUTOGNSS_DEPENDENCIES = libglib2 host-pkgconf

$(eval $(cmake-package))
