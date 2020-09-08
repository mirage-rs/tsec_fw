#------------------------------------------------------------------------------
# The source files for building the firmware blob.
#------------------------------------------------------------------------------
KEYGENLDR_SRC     = $(CURDIR)/src
KEYGENLDR_MAIN    = $(KEYGENLDR_SRC)/keygenldr_main.fuc
LIB_SOURCES       = $(wildcard $(LIBDIR)/*.fuc)

#------------------------------------------------------------------------------
.PHONY: all clean
#------------------------------------------------------------------------------

all: keygenldr.bin

keygenldr.bin: keygenldr_real.fuc
	envyas -m falcon -V fuc5 -F crypt $? -i -o $@

keygenldr_real.fuc: $(KEYGENLDR_MAIN) $(LIB_SOURCES)
	m4 -I $(LIBDIR) -I $(KEYGENLDR_SRC) $(KEYGENLDR_MAIN) > $@

clean:
	@rm -f keygenldr_real.fuc keygenldr.bin
