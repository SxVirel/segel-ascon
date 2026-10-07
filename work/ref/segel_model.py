#!/usr/bin/env python3
"""
Model referensi "Segel Ascon" — tingkat register, bukan RTL.

Isi:
  1. Cek implementasi referensi pyascon terhadap 1.089 KAT resmi Ascon-AEAD128 (ascon-c).
  2. Model perangkat keras: state Ascon 5 x 64 bit disimpan di register file
     baseline 10 x 32 bit, lalu MAC dihitung dengan urutan langkah yang sama
     seperti FSM rencana (LOAD, p12, MID, p12, FINAL). Hasilnya dibandingkan
     dengan pyascon dan KAT.
  3. Bukti kebocoran kunci bila state boleh dibaca balik (alasan Security Design).
  4. Hitungan siklus dari protokol bus baseline (2 siklus per byte).

Jalankan: python work/ref/segel_model.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "pyascon"))
import ascon  # noqa: E402  (pyascon, implementasi referensi resmi, CC0)

MASK64 = (1 << 64) - 1
IV_AEAD128 = 0x00001000808C0001  # NIST SP 800-232, Algorithm 3


# ---------------------------------------------------------------------------
# 1. pyascon vs KAT resmi
# ---------------------------------------------------------------------------
def load_kat(path):
    entries, cur = [], {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                if cur:
                    entries.append(cur)
                    cur = {}
                continue
            k, _, v = line.partition("=")
            cur[k.strip()] = v.strip()
    if cur:
        entries.append(cur)
    return entries


def check_pyascon_against_kat(entries):
    bad = 0
    for e in entries:
        key, nonce = bytes.fromhex(e["Key"]), bytes.fromhex(e["Nonce"])
        pt, ad, ct = bytes.fromhex(e["PT"]), bytes.fromhex(e["AD"]), bytes.fromhex(e["CT"])
        if ascon.ascon_encrypt(key, nonce, ad, pt) != ct:
            bad += 1
    return bad


# ---------------------------------------------------------------------------
# 2. Model perangkat keras di register file 10 x 32 bit
# ---------------------------------------------------------------------------
def rotr(x, r):
    return ((x >> r) | (x << (64 - r))) & MASK64


def regs_get(regs, i):
    """Word Ascon x_i = {reg[2i+1], reg[2i]} (bagian rendah di register genap)."""
    return (regs[2 * i + 1] << 32) | regs[2 * i]


def regs_set(regs, i, v):
    regs[2 * i] = v & 0xFFFFFFFF
    regs[2 * i + 1] = (v >> 32) & 0xFFFFFFFF


def round_constant(r):
    """Konstanta ronde ke-r (0..11) dari p12 = {~r[3:0], r[3:0]} -> tanpa ROM."""
    return (((~r) & 0xF) << 4) | r


def ascon_round(x, c):
    """Satu ronde Ascon (sama dengan pyascon.ascon_permutation, ditulis per langkah)."""
    x = list(x)
    x[2] ^= c
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1]
    t = [(~x[i] & MASK64) & x[(i + 1) % 5] for i in range(5)]
    for i in range(5):
        x[i] ^= t[(i + 1) % 5]
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] ^= MASK64
    x[0] ^= rotr(x[0], 19) ^ rotr(x[0], 28)
    x[1] ^= rotr(x[1], 61) ^ rotr(x[1], 39)
    x[2] ^= rotr(x[2], 1) ^ rotr(x[2], 6)
    x[3] ^= rotr(x[3], 10) ^ rotr(x[3], 17)
    x[4] ^= rotr(x[4], 7) ^ rotr(x[4], 41)
    return x


class SegelModel:
    """
    Model perilaku desain. Alamat bus mengikuti baseline:
      alamat 0..39  = register 0..9, byte = alamat[1:0] (little-endian)
      alamat 40..55 = KEY byte 0..15 (tulis-saja)
      alamat 56     = CTRL (tulis) / STATUS (baca)
      alamat 57     = VERSION (baca)
      alamat 63     = perintah 1 ronde SHA-256 (baseline, hanya mode SHA)
    """

    CTRL_MODE, CTRL_START, CTRL_CLEAR, CTRL_KEYCLR = 0x01, 0x02, 0x04, 0x08
    VERSION = 0xA1

    def __init__(self, cycles_per_round=1):
        self.cpr = cycles_per_round  # R1 = 1, R2 = 2, R8 = 9 (8 siklus S-box + 1 linear)
        self.reset()

    def reset(self):
        self.regs = [0] * 10
        self.key = bytearray(16)
        self.mode_ascon = False
        self.key_valid = False
        self.done = False
        self.err = False
        self.cycles_compute = 0
        self.trace = []  # snapshot state internal per siklus (untuk analisis kebocoran)

    # --- bus ---
    def write(self, addr, data):
        if addr < 40:
            if self.mode_ascon and addr < 24:
                return  # register 0..5 tidak bisa ditulis di mode Ascon (harus nol saat START)
            reg, byte = addr >> 2, addr & 3
            if self.mode_ascon and self.done:
                self.done = False  # tulis nonce baru -> tag lama tidak berlaku
            self.regs[reg] &= ~(0xFF << (8 * byte)) & 0xFFFFFFFF
            self.regs[reg] |= data << (8 * byte)
        elif addr < 56:
            i = addr - 40
            if i == 0:
                self.key_valid = False
            self.key[i] = data
            if i == 15:
                self.key_valid = True
        elif addr == 56:
            self._ctrl(data)
        elif addr == 63:
            if self.mode_ascon:
                self.err = True  # perintah SHA ditolak di mode Ascon
            # (fungsi ronde SHA-256 baseline tidak dimodelkan di sini)

    def read(self, addr):
        if addr < 40:
            if not self.mode_ascon:
                reg, byte = addr >> 2, addr & 3
                return (self.regs[reg] >> (8 * byte)) & 0xFF
            if addr < 24:
                return 0  # register 0..5 tidak pernah terbaca di mode Ascon
            reg, byte = addr >> 2, addr & 3
            return (self.regs[reg] >> (8 * byte)) & 0xFF  # jendela nonce/tag
        if addr < 56:
            return 0  # kunci tulis-saja
        if addr == 56:
            # STATUS = {3'b0, ERR, KEY_VALID, MODE, DONE, BUSY}; sama dengan uo_out[6:2]
            return (int(self.done) << 1) | (int(self.mode_ascon) << 2) | \
                   (int(self.key_valid) << 3) | (int(self.err) << 4)
        if addr == 57:
            return self.VERSION
        return 0

    def _zeroize_state(self):
        self.regs = [0] * 10
        self.done = False

    def _ctrl(self, v):
        self.err = False
        if v & self.CTRL_KEYCLR:
            self.key = bytearray(16)
            self.key_valid = False
        new_mode = bool(v & self.CTRL_MODE)
        if new_mode != self.mode_ascon or v & self.CTRL_CLEAR:
            self._zeroize_state()  # ganti mode selalu menghapus state
            self.mode_ascon = new_mode
        if v & self.CTRL_START:
            if not (self.mode_ascon and self.key_valid):
                self.err = True
                return
            self._run_mac()

    # --- FSM MAC: Ascon-AEAD128, AD kosong, plaintext kosong, nonce = reg 6..9 ---
    def _k(self):
        return int.from_bytes(self.key[0:8], "little"), int.from_bytes(self.key[8:16], "little")

    def _snap(self, label):
        self.trace.append((label, [regs_get(self.regs, i) for i in range(5)]))

    def _p12(self, tag):
        for r in range(12):
            x = ascon_round([regs_get(self.regs, i) for i in range(5)], round_constant(r))
            for i in range(5):
                regs_set(self.regs, i, x[i])
            self.cycles_compute += self.cpr
            self._snap(f"{tag}-r{r + 1}")

    def _run_mac(self):
        k0, k1 = self._k()
        self.cycles_compute = 0
        self.trace = []
        # LOAD (1 siklus): x0 = IV, x1||x2 = K, x3||x4 = nonce (sudah ditulis host)
        regs_set(self.regs, 0, IV_AEAD128)
        regs_set(self.regs, 1, k0)
        regs_set(self.regs, 2, k1)
        self.cycles_compute += 1
        self._snap("load")
        self._p12("init")
        # MID (1 siklus, semua XOR di word berbeda):
        #   x3,x4 ^= K (akhir inisialisasi), x4 ^= 1<<63 (pemisah domain, AD kosong),
        #   x0 ^= 1 (padding plaintext kosong), x2,x3 ^= K (awal finalisasi: S ^ (0^128||K||0^64))
        x = [regs_get(self.regs, i) for i in range(5)]
        x[0] ^= 1
        x[2] ^= k0
        x[3] ^= k0 ^ k1
        x[4] ^= k1 ^ (1 << 63)
        for i in range(5):
            regs_set(self.regs, i, x[i])
        self.cycles_compute += 1
        self._snap("mid")
        self._p12("final")
        self._snap("final-before-tag-xor")
        # FINAL (1 siklus): tag = x3||x4 ^ K, register 0..5 dinolkan
        x3 = regs_get(self.regs, 3) ^ k0
        x4 = regs_get(self.regs, 4) ^ k1
        for i in range(3):
            regs_set(self.regs, i, 0)
        regs_set(self.regs, 3, x3)
        regs_set(self.regs, 4, x4)
        self.cycles_compute += 1
        self.done = True


def host_mac(dev, key, nonce, load_key=True):
    """Urutan perintah host untuk satu MAC; mengembalikan tag 16 byte."""
    if load_key:
        for i, b in enumerate(key):
            dev.write(40 + i, b)
    dev.write(56, SegelModel.CTRL_MODE)  # masuk mode Ascon (state dinolkan)
    for i, b in enumerate(nonce):
        dev.write(24 + i, b)  # nonce -> x3||x4 = register 6..9
    dev.write(56, SegelModel.CTRL_MODE | SegelModel.CTRL_START)
    assert dev.done and not dev.err
    return bytes(dev.read(24 + i) for i in range(16))


# ---------------------------------------------------------------------------
# 3. Kebocoran kunci bila state boleh dibaca balik
# ---------------------------------------------------------------------------
def sbox_table():
    """Tabel S-box 5 bit Ascon, diturunkan dari ascon_round pada satu kolom."""
    tab = []
    for v in range(32):
        x = [((v >> (4 - i)) & 1) for i in range(5)]  # x0 = bit paling kiri
        y = list(x)
        y[0] ^= y[4]; y[4] ^= y[3]; y[2] ^= y[1]
        t = [(1 - y[i]) & y[(i + 1) % 5] for i in range(5)]
        for i in range(5):
            y[i] ^= t[(i + 1) % 5]
        y[1] ^= y[0]; y[0] ^= y[4]; y[3] ^= y[2]; y[2] ^= 1
        tab.append(sum(y[i] << (4 - i) for i in range(5)))
    return tab


SBOX = sbox_table()
SBOX_INV = [SBOX.index(i) for i in range(32)]
ROT = [(19, 28), (61, 39), (1, 6), (10, 17), (7, 41)]


def linear_inverse(x, a, b):
    """Balik y = z ^ rotr(z,a) ^ rotr(z,b): cari z dengan eliminasi Gauss pada matriks 64x64 di GF(2)."""
    cols = []
    for i in range(64):
        e = 1 << i
        cols.append(e ^ rotr(e, a) ^ rotr(e, b))
    mat =[[(cols[j] >> i) & 1 for j in range(64)] + [(x >> i) & 1] for i in range(64)]
    r = 0
    for c in range(64):
        p = next((k for k in range(r, 64) if mat[k][c]), None)
        assert p is not None, "lapisan linear tidak invertibel?"
        mat[r], mat[p] = mat[p], mat[r]
        for k in range(64):
            if k != r and mat[k][c]:
                mat[k] = [u ^ v for u, v in zip(mat[k], mat[r])]
        r += 1
    return sum(mat[i][64] << i for i in range(64))


def ascon_round_inverse(x, c):
    x = [linear_inverse(x[i], *ROT[i]) for i in range(5)]
    y = [0] * 5
    for bit in range(64):
        v = sum(((x[i] >> bit) & 1) << (4 - i) for i in range(5))
        u = SBOX_INV[v]
        for i in range(5):
            y[i] |= ((u >> (4 - i)) & 1) << bit
    y[2] ^= c
    return y


def leak_demo(key, nonce):
    dev = SegelModel()
    tag = host_mac(dev, key, nonce)
    trace = dict(dev.trace)
    k0, k1 = int.from_bytes(key[:8], "little"), int.from_bytes(key[8:], "little")
    results = {}

    # L1: state penuh sesudah p12 finalisasi, sebelum XOR kunci -> K = (x3||x4) ^ tag
    s = trace["final-before-tag-xor"]
    t0, t1 = int.from_bytes(tag[:8], "little"), int.from_bytes(tag[8:], "little")
    results["L1 (sesudah finalisasi, sebelum XOR tag)"] = (s[3] ^ t0, s[4] ^ t1) == (k0, k1)

    # L2: state sesudah r ronde inisialisasi (r = 1..12) -> balik r ronde -> x1||x2 = K
    ok = True
    for r in range(1, 13):
        x = trace[f"init-r{r}"]
        for rr in reversed(range(r)):
            x = ascon_round_inverse(x, round_constant(rr))
        ok &= (x[1], x[2]) == (k0, k1) and x[0] == IV_AEAD128
    results["L2 (selama inisialisasi, ronde 1..12)"] = ok
    return results


# ---------------------------------------------------------------------------
# 4. Hitungan siklus (protokol bus baseline: 2 siklus per byte, 2 siklus ganti mode)
# ---------------------------------------------------------------------------
def cycle_budget(compute):
    w = {
        "tulis nonce (16 byte x 2)": 32,
        "tulis CTRL START (1 byte x 2)": 2,
        "hitung di chip": compute,
        "ganti mode bus tulis->baca": 2,
        "baca tag (16 byte x 2)": 32,
        "ganti mode bus baca->tulis": 2,
    }
    return w, sum(w.values())


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    kat = load_kat(os.path.join(HERE, "kat", "LWC_AEAD_KAT_128_128.txt"))
    bad = check_pyascon_against_kat(kat)
    print(f"[1] pyascon vs KAT resmi: {len(kat) - bad}/{len(kat)} cocok")
    assert bad == 0

    # KAT dengan PT kosong & AD kosong = persis mode MAC kita
    mac_kats = [e for e in kat if e["PT"] == "" and e["AD"] == ""]
    for e in mac_kats:
        tag = host_mac(SegelModel(), bytes.fromhex(e["Key"]), bytes.fromhex(e["Nonce"]))
        assert tag.hex().upper() == e["CT"], (e["Count"], tag.hex())
    print(f"[2] model register 10x32 vs KAT (PT & AD kosong): {len(mac_kats)}/{len(mac_kats)} cocok "
          f"(Count {', '.join(e['Count'] for e in mac_kats)})")

    rnd = 0
    for _ in range(300):
        key, nonce = os.urandom(16), os.urandom(16)
        dev = SegelModel()
        tag = host_mac(dev, key, nonce)
        assert tag == ascon.ascon_encrypt(key, nonce, b"", b""), "model != pyascon"
        assert ascon.ascon_decrypt(key, nonce, b"", tag) == b"", "verifikasi pembaca gagal"
        assert ascon.ascon_decrypt(key, bytes([nonce[0] ^ 1]) + nonce[1:], b"", tag) is None
        # keamanan logis: kunci dan register 0..5 terbaca 0, jendela 6..9 = tag
        assert all(dev.read(a) == 0 for a in range(0, 24)) and all(dev.read(a) == 0 for a in range(40, 56))
        assert dev.cycles_compute == 27
        rnd += 1
    print(f"[2] model vs pyascon, kunci/nonce acak: {rnd}/{rnd} cocok; verifikasi pembaca OK; "
          f"tantangan diubah -> ditolak; kunci & reg 0..5 terbaca 0; siklus hitung selalu 27")

    # tulisan sampah ke register 0..5 di mode Ascon tidak boleh mengubah hasil
    key, nonce = os.urandom(16), os.urandom(16)
    dev = SegelModel()
    for i, b in enumerate(key):
        dev.write(40 + i, b)
    dev.write(56, SegelModel.CTRL_MODE)
    for a in range(24):
        dev.write(a, 0xA5)
    for i, b in enumerate(nonce):
        dev.write(24 + i, b)
    dev.write(56, SegelModel.CTRL_MODE | SegelModel.CTRL_START)
    assert bytes(dev.read(24 + i) for i in range(16)) == ascon.ascon_encrypt(key, nonce, b"", b"")
    # START tanpa kunci -> ERR
    dev = SegelModel()
    dev.write(56, SegelModel.CTRL_MODE | SegelModel.CTRL_START)
    assert dev.err and not dev.done and dev.read(56) == 0b10100
    print("    tulis ke reg 0..5 di mode Ascon diabaikan: OK; START tanpa kunci -> ERR: OK")

    variants = {}
    for name, cpr in (("R1", 1), ("R2", 2), ("R8", 9)):
        d = SegelModel(cycles_per_round=cpr)
        assert host_mac(d, key, nonce) == ascon.ascon_encrypt(key, nonce, b"", b"")
        variants[name] = d.cycles_compute
    print("    siklus hitung per varian: " + ", ".join(f"{k} = {v}" for k, v in variants.items()))

    res = leak_demo(os.urandom(16), os.urandom(16))
    for k, v in res.items():
        print(f"[3] kunci bocor jika state terbaca pada {k}: {'YA' if v else 'tidak'}")

    for comp in variants.values():
        parts, total = cycle_budget(comp)
        print(f"[4] siklus per MAC (kunci sudah dimuat, hitung {comp}): {total}")
        for k, v in parts.items():
            print(f"      {k:34s} {v:4d}")
    print("    muat kunci sekali sesudah reset: 16 byte x 2 = 32 siklus; masuk mode Ascon: 2 siklus")


if __name__ == "__main__":
    main()
