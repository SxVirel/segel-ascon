# Makefile cocotb untuk desain lengkap Segel Ascon.
# Jalankan dari folder ini:  make            (desain utama, SHARED_STATE=1)
#                            make SHARED_STATE=0 MODULE=test_segel   (desain pembanding area)
# See https://docs.cocotb.org/en/stable/quickstart.html for more info

SIM ?= icarus
TOPLEVEL_LANG ?= verilog
SRC_DIR = $(PWD)/../rtl
PROJECT_SOURCES = project.v sha256_round.v ascon_round.v

SHARED_STATE ?= 1
export SEGEL_SHARED_STATE = $(SHARED_STATE)

SIM_BUILD        = sim_build/rtl_shared$(SHARED_STATE)
VERILOG_SOURCES += $(addprefix $(SRC_DIR)/,$(PROJECT_SOURCES))
VERILOG_SOURCES += $(PWD)/tb.v
COMPILE_ARGS    += -I$(SRC_DIR)
COMPILE_ARGS    += -Ptb.SHARED_STATE=$(SHARED_STATE)
TOPLEVEL = tb

# test (test.py) dan test_extra (test_extra.py) adalah test baseline SHA-256,
# dipakai TANPA diubah langsung dari folder baseline. test_segel = test baru.
export PYTHONPATH := $(PWD)/../baseline-sha256/test:$(PYTHONPATH)
MODULE ?= test,test_extra,test_segel

# include cocotb's make rules to take care of the simulator setup
include $(shell cocotb-config --makefiles)/Makefile.sim
