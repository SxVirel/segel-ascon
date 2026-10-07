#!/usr/bin/env python3
"""
Ringkas hasil sintesis Yosys (<folder>/*.stat.txt) menjadi tabel markdown + summary.json.

Semua angka = ESTIMASI sesudah sintesis (jumlah sel dan luas sel), BUKAN hasil place & route.
Utilisasi dihitung sebagai luas sel / luas core tile (kalibrasi:
untuk baseline resmi, 32.567 / 72.565 um^2 = 44,9 % vs Final_Util resmi 45,1 %).
"""
import json
import os
import re
import sys

NAND2_UM2 = 3.7536  # 1 GE = luas sky130_fd_sc_hd__nand2_1

# Angka resmi baseline: github.com/TinyTapeout/tinytapeout-07, projects/tt_um_xeniarose_sha256/stats/synthesis-stats.txt
OFFICIAL_BASELINE = {"cells": 2881, "ff": 329, "area": 32567.4848}

# Luas core per ukuran tile (um^2): CoreArea_um^2 di metrics.csv proyek TT07 (github.com/TinyTapeout/tinytapeout-07).
# 4x2 tidak punya data lengkap di shuttle TT07 -> interpolasi linear dari 3x2 dan 6x2 [ESTIMASI].
CORE_AREA = {"2x2": 72564.6, "3x2": 110873.8, "4x2": 149183.1}

ROWS = [
    ("baseline", "Baseline SHA-256 (alur Yosys kita)"),
    ("segel_shared", "**Segel Ascon** (state Ascon berbagi register baseline)"),
    ("segel_separate", "Pembanding: Segel Ascon dengan state Ascon terpisah"),
    ("ascon_round", "Blok `ascon_round` saja (1 ronde, kombinasional)"),
    ("sha256_round", "Blok `sha256_round` saja (kombinasional)"),
]


def parse(path):
    txt = open(path).read()
    m = re.search(r"Number of cells:\s+(\d+)", txt) or re.search(r"^\s*(\d+)\s+cells\s*$", txt, re.M)
    area = re.search(r"Chip area for module .*?:\s+([0-9.]+)", txt)
    ff = 0
    for name, n in re.findall(r"(sky130_fd_sc_hd__\w+)\s+(\d+)", txt):
        if "__df" in name or "__edf" in name:
            ff += int(n)
    return {"cells": int(m.group(1)), "area": float(area.group(1)), "ff": ff}


def util(area):
    return {t: 100.0 * area / a for t, a in CORE_AREA.items()}


def fmt_row(label, d):
    u = util(d["area"])
    return (f"| {label} | {d['cells']:,} | {d['ff']:,} | {d['area']:,.0f} | {d['area'] / NAND2_UM2:,.0f} | "
            + " | ".join(f"{u[t]:.0f} %" for t in CORE_AREA) + " |")


def main(folder):
    res = {}
    for key, _ in ROWS:
        p = os.path.join(folder, f"{key}.stat.txt")
        if os.path.exists(p):
            res[key] = parse(p)

    print("## Hasil sintesis Yosys — sky130_fd_sc_hd (sel _2), ESTIMASI sesudah sintesis\n")
    print("| Desain | Sel | Flip-flop | Luas sel (um²) | GE | Utilisasi 2x2 | Utilisasi 3x2 | Utilisasi 4x2* |")
    print("|---|---|---|---|---|---|---|---|")
    print(fmt_row("Baseline SHA-256 (**angka resmi TT07**)", OFFICIAL_BASELINE))
    for key, label in ROWS:
        if key in res:
            print(fmt_row(label, res[key]))
    print("\n*Luas core 4x2 = interpolasi linear dari data 3x2 dan 6x2 TT07 [ESTIMASI]. "
          "1 GE = 3,7536 um² (nand2_1).\n")

    out = {"results": res, "official_baseline": OFFICIAL_BASELINE, "core_area_um2": CORE_AREA}
    if "baseline" in res:
        cal = OFFICIAL_BASELINE["area"] / res["baseline"]["area"]
        out["calibration_area_official_over_ours"] = cal
        print(f"- **Kalibrasi:** untuk baseline, luas resmi / luas alur kita = {cal:.3f} "
              f"(sel: {OFFICIAL_BASELINE['cells']} resmi vs {res['baseline']['cells']} kita).")
        if "segel_shared" in res:
            s = res["segel_shared"]
            add = s["area"] - res["baseline"]["area"]
            cal_area = s["area"] * cal
            out["segel_added_area_um2"] = add
            out["segel_area_calibrated_um2"] = cal_area
            print(f"- **Tambahan Segel Ascon vs baseline (alur sama):** +{add:,.0f} um² "
                  f"(+{add / NAND2_UM2:,.0f} GE, +{100 * add / res['baseline']['area']:.0f} %), "
                  f"flip-flop {res['baseline']['ff']} -> {s['ff']}.")
            print(f"- **Luas Segel Ascon setelah dikalibrasi ke skala resmi:** {cal_area:,.0f} um² "
                  f"({cal_area / NAND2_UM2:,.0f} GE) -> utilisasi "
                  + ", ".join(f"{t} {u:.0f} %" for t, u in util(cal_area).items()) + ".")
    if "segel_shared" in res and "segel_separate" in res:
        sh, se = res["segel_shared"], res["segel_separate"]
        save = se["area"] - sh["area"]
        out["sharing_saving_um2"] = save
        print(f"- **Penghematan dari berbagi register:** state terpisah {se['area']:,.0f} um² vs berbagi "
              f"{sh['area']:,.0f} um² -> hemat {save:,.0f} um² ({save / NAND2_UM2:,.0f} GE, "
              f"{100 * save / se['area']:.1f} % dari desain pembanding); flip-flop {se['ff']} -> {sh['ff']}.")
    fpga = {}
    for key, label in (("baseline_cyclonev", "Baseline SHA-256"), ("segel_cyclonev", "**Segel Ascon**")):
        p = os.path.join(folder, f"{key}.stat.txt")
        if not os.path.exists(p):
            continue
        txt = open(p).read()
        luts = sum(int(n) for n in re.findall(r"MISTRAL_ALUT\w*\s+(\d+)", txt))
        ffs = sum(int(n) for n in re.findall(r"MISTRAL_FF\s+(\d+)", txt))
        mlab = sum(int(n) for n in re.findall(r"MISTRAL_MLAB\s+(\d+)", txt))
        fpga[key] = {"label": label, "lut": luts, "ff": ffs, "mlab": mlab}
    if fpga:
        print("\n## Estimasi FPGA Cyclone V (Yosys `synth_intel_alm`, BUKAN Quartus)\n")
        print("| Desain | LUT (MISTRAL_ALUT*) | Flip-flop (MISTRAL_FF) | MLAB |")
        print("|---|---|---|---|")
        for d in fpga.values():
            print(f"| {d['label']} | {d['lut']:,} | {d['ff']:,} | {d['mlab']} |")
        print("\nSatu ALM Cyclone V memuat hingga 2 LUT dan 4 flip-flop, jadi jumlah ALM diperkirakan "
              "antara LUT/2 dan LUT; angka ALM pasti hanya dari Quartus.")
        out["fpga_cyclonev"] = fpga
    with open(os.path.join(folder, "summary.json"), "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "work/synth/out")
