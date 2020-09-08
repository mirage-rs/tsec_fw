#------------------------------------------------------------------------------
# The source files for building the firmware blob.
#------------------------------------------------------------------------------
BOOT_SRC     = $(CURDIR)/src
BOOT_MAIN    = $(BOOT_SRC)/boot_main.fuc
LIB_SOURCES  = $(wildcard $(LIBDIR)/*.fuc)

#------------------------------------------------------------------------------
.PHONY: all clean
#------------------------------------------------------------------------------

all: boot.bin

boot.bin: boot_real.fuc
	envyas -m falcon -V fuc5 -F crypt $? -i -o $@

boot_real.fuc: $(BOOT_MAIN) $(LIB_SOURCES)
	m4 -I $(LIBDIR) -I $(BOOT_SRC) $(BOOT_MAIN) > $@

clean:
	@rm -f boot_real.fuc boot.bin
