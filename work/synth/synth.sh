#!/usr/bin/env bash
# Sintesis kasar dengan Yosys + pustaka sel sky130_fd_sc_hd (hanya varian _2, meniru laporan TT07).
# Hasilnya ESTIMASI sesudah sintesis, BUKAN hasil place & route.
#
# Pemakaian (dari root repo):  bash work/synth/synth.sh <path sky130_fd_sc_hd__tt_025C_1v80.lib> [folder_keluaran]
set -euo pipefail

LIB_FULL="$1"
OUT="${2:-work/synth/out}"
mkdir -p "$OUT"

python3 work/synth/filter_lib.py "$LIB_FULL" "$OUT/sky130_hd_x2.lib"
LIB2="$OUT/sky130_hd_x2.lib"
SEGEL="work/rtl/project.v work/rtl/sha256_round.v work/rtl/ascon_round.v"

run() {
  local name="$1" top="$2" files="$3" shared="${4:-}"
  local chp=""
  if [ -n "$shared" ]; then chp="chparam -set SHARED_STATE $shared $top;"; fi
  echo "== $name"
  yosys -q -l "$OUT/$name.log" -p "
    read_verilog $files;
    $chp
    synth -flatten -top $top;
    dfflibmap -liberty $LIB2;
    abc -liberty $LIB2;
    opt_clean -purge;
    tee -o $OUT/$name.stat.txt stat -liberty $LIB_FULL;
  "
}

run baseline       tt_um_xeniarose_sha256    "work/baseline-sha256/src/project.v"
run segel_shared   tt_um_sxvirel_segel_ascon "$SEGEL" 1
run segel_separate tt_um_sxvirel_segel_ascon "$SEGEL" 0
run ascon_round    ascon_round               "work/rtl/ascon_round.v"
run sha256_round   sha256_round              "work/rtl/sha256_round.v"

# Estimasi FPGA Cyclone V (chip DE10-Nano) dengan pemeta Intel ALM bawaan Yosys.
# BUKAN hasil Quartus; dipakai hanya sebagai orde besaran untuk tabel resource template.
fpga() {
  local name="$1" top="$2" files="$3"
  echo "== $name (cyclonev)"
  yosys -q -l "$OUT/$name.log" -p "
    read_verilog $files;
    synth_intel_alm -family cyclonev -top $top;
    tee -o $OUT/$name.stat.txt stat;
  " || echo "synth_intel_alm gagal untuk $name"
}
fpga baseline_cyclonev tt_um_xeniarose_sha256    "work/baseline-sha256/src/project.v"
fpga segel_cyclonev    tt_um_sxvirel_segel_ascon "$SEGEL"

python3 work/synth/summarize.py "$OUT" | tee "$OUT/summary.md"
