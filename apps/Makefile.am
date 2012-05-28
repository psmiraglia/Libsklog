AM_CFLAGS = \
	-Wall -Werror -g \
	-DBIN_PREFIX=\"@bindir@\" \
	-I$(srcdir)/../include

bin_PROGRAMS = \
	unode \
	tnode \
	vnode

unode_SOURCES = unode.c
unode_LDADD = ../lib/libsklog.la

tnode_SOURCES = tnode.c
tnode_LDADD = ../lib/libsklog.la

vnode_SOURCES = vnode.c
vnode_LDADD = ../lib/libsklog.la
