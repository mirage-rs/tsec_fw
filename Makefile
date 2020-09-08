#------------------------------------------------------------------------------
.SUFFIXES:
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Central project directories that will be used by subdirectory Makefiles.
#------------------------------------------------------------------------------
export TOPDIR    ?= $(CURDIR)
export LIBDIR    ?= $(TOPDIR)/lib
export STAGESDIR ?= $(TOPDIR)/stages
export TOOLSDIR  ?= $(TOPDIR)/tools

OUTDIR           ?= $(TOPDIR)/output

#------------------------------------------------------------------------------
# STAGES: A list of the individual firmware stages to build.
#------------------------------------------------------------------------------
STAGES := boot keygenldr

#------------------------------------------------------------------------------
.PHONY: all clean $(STAGES)
#------------------------------------------------------------------------------

all: $(STAGES)
	@mkdir $(OUTDIR)
	@cp $(STAGESDIR)/boot/boot.bin $(OUTDIR)
	@cp $(STAGESDIR)/keygenldr/keygenldr.bin $(OUTDIR)

boot:
	$(MAKE) -C $(STAGESDIR)/boot all

keygenldr:
	$(MAKE) -C $(STAGESDIR)/keygenldr all

clean:
	$(MAKE) -C $(STAGESDIR)/boot clean
	$(MAKE) -C $(STAGESDIR)/keygenldr clean
	@rm -rf $(TOPDIR)/output
