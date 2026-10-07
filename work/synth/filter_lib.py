#!/usr/bin/env python3
"""
Saring pustaka sel sky130_fd_sc_hd (.lib) agar hanya berisi sel logika varian drive "_2".

Alasan: laporan sintesis resmi TT07 untuk baseline (github.com/TinyTapeout/tinytapeout-07, projects/
tt_um_xeniarose_sha256/stats/synthesis-stats.txt) hanya memakai sel *_2 untuk logika dan
flip-flop. Dengan menyaring seperti ini, hasil Yosys kita bisa dibandingkan dengan angka resmi.
Sel khusus (clock buffer, delay, tap, fill, diode, low-power, scan, latch) dibuang.

Pemakaian: python3 filter_lib.py <lib_masuk> <lib_keluar>
"""
import re
import sys

EXCLUDE = ("lpflow", "clkbuf", "clkinv", "clkdly", "dlygate", "dlymetal", "probe", "diode",
           "tapvpwr", "tapvgnd", "tap_", "fill", "decap", "conb", "macro", "sdf", "sedf",
           "dlx", "dlr", "einv", "ebuf", "bufbuf")

CELL_RE = re.compile(r'^\s*cell\s*\(\s*"?([A-Za-z0-9_]+)"?\s*\)\s*\{', re.M)


def keep(name):
    return name.endswith("_2") and not any(x in name for x in EXCLUDE)


def block_end(text, start):
    """Indeks sesudah kurung kurawal penutup blok yang dibuka di text[start:]."""
    depth, i, in_str = 0, text.index("{", start), False
    while i < len(text):
        ch = text[i]
        if not in_str and text.startswith("/*", i):
            i = text.index("*/", i + 2) + 2  # lewati komentar
            continue
        if ch == '"' and text[i - 1] != "\\":
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    raise ValueError("blok cell tidak tertutup")


def main(src, dst):
    text = open(src).read()
    out, pos, kept, dropped = [], 0, [], 0
    for m in CELL_RE.finditer(text):
        if m.start() < pos:
            continue  # di dalam blok yang sudah dilewati
        end = block_end(text, m.start())
        out.append(text[pos:m.start()])
        if keep(m.group(1)):
            out.append(text[m.start():end])
            kept.append(m.group(1))
        else:
            dropped += 1
        pos = end
    out.append(text[pos:])
    with open(dst, "w") as f:
        f.write("".join(out))
    print(f"filter_lib: {len(kept)} sel disimpan, {dropped} dibuang -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
