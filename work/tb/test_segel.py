# SPDX-License-Identifier: Apache-2.0
"""
Test desain lengkap Segel Ascon (work/rtl/project.v).

Dijalankan bersama test baseline SHA-256 (test.py dan test_extra.py, tidak diubah),
lihat Makefile. Isi file ini:
  - MAC Ascon lewat bus vs KAT resmi dan vs pyascon (implementasi referensi resmi);
  - uji keamanan S1..S7 (tabel Security Design di README.md);
  - mode SHA-256 tetap benar sesudah mode Ascon dipakai;
  - pengukuran siklus (disimpan ke measurements_segel_shared<N>.json).

Catatan protokol: sama dengan baseline. Host memasang alamat + data, menaikkan io_clk
1 siklus, lalu menurunkannya 1 siklus (2 siklus per byte). Ganti arah baca/tulis 2 siklus.
"""
import json
import os
import random
import struct
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge
from cocotb.utils import get_sim_time

HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(HERE, "..", "ref")
sys.path.insert(0, REF)
import segel_model  # noqa: E402  (ikut menambahkan pyascon ke sys.path)
import ascon  # noqa: E402  pyascon, implementasi referensi resmi (CC0)

# Pembantu SHA-256 dari test tambahan baseline
from test_extra import H0, NIST_VECTORS, pad, schedule  # noqa: E402
from test_extra import K as SHA_K  # noqa: E402
from test_extra import _round as sha_round_model  # noqa: E402

CLK_PERIOD_US = 10
IO_RWSEL = 0x40
IO_CLK = 0x80
MODE_READ, MODE_WRITE = 1, 2

ADDR_WIN, ADDR_KEY, ADDR_CTRL, ADDR_VERSION, ADDR_SHA = 24, 40, 56, 57, 63
CTRL_MODE, CTRL_START, CTRL_CLEAR, CTRL_KEYCLR = 0x01, 0x02, 0x04, 0x08
ST_BUSY, ST_DONE, ST_MODE, ST_KEYV, ST_ERR = 0x01, 0x02, 0x04, 0x08, 0x10

SHARED = os.environ.get("SEGEL_SHARED_STATE", "1") == "1"
MEAS = {"shared_state": SHARED}
MEAS_FILE = f"measurements_segel_shared{int(SHARED)}.json"


def save_measurements():
    with open(MEAS_FILE, "w") as f:
        json.dump(MEAS, f, indent=2)


def ref_tag(key, nonce):
    """Tag acuan: Ascon-AEAD128 dengan AD dan plaintext kosong (pyascon)."""
    return ascon.ascon_encrypt(key, nonce, b"", b"")


def now_us():
    return get_sim_time(units="us")


def cycles(t0, t1):
    return round((t1 - t0) / CLK_PERIOD_US)


# ---------------------------------------------------------------------------
# Bus host
# ---------------------------------------------------------------------------
class Bus:
    def __init__(self, dut):
        self.dut = dut
        self.mode = None

    async def set_mode(self, mode):
        if self.mode != mode:
            self.dut.ui_in.value = IO_RWSEL if mode == MODE_READ else 0
            await ClockCycles(self.dut.clk, 2)
            self.mode = mode

    async def write(self, addr, byte, hold=1):
        """Tulis 1 byte. Mengembalikan waktu tepi clock saat tulisan diterima."""
        await self.set_mode(MODE_WRITE)
        self.dut.uio_in.value = byte
        self.dut.ui_in.value = IO_CLK | addr
        await ClockCycles(self.dut.clk, 1)
        t_strobe = now_us()
        if hold > 1:
            await ClockCycles(self.dut.clk, hold - 1)
        self.dut.ui_in.value = addr
        await ClockCycles(self.dut.clk, 1)
        return t_strobe

    async def read(self, addr):
        await self.set_mode(MODE_READ)
        self.dut.ui_in.value = IO_CLK | IO_RWSEL | addr
        await ClockCycles(self.dut.clk, 1)
        self.dut.ui_in.value = IO_RWSEL | addr
        await ClockCycles(self.dut.clk, 1)
        return int(self.dut.uio_out.value)

    async def write32(self, addr, word):
        for i in range(4):
            await self.write(addr + i, (word >> (8 * i)) & 0xFF)

    async def read32(self, addr):
        word = 0
        for i in range(4):
            word |= (await self.read(addr + i)) << (8 * i)
        return word

    def pins(self):
        """STATUS dari pin uo_out[6:2] = {ERR, KEY_VALID, MODE, DONE, BUSY}."""
        return (int(self.dut.uo_out.value) >> 2) & 0x1F


async def init(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_US, units="us").start())
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 1)
    return Bus(dut)


async def pulse_reset(bus):
    dut = bus.dut
    dut.ui_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 1)
    bus.mode = None


async def load_key(bus, key):
    for i, b in enumerate(key):
        await bus.write(ADDR_KEY + i, b)


async def wait_done(bus, limit=300):
    """Host menunggu pin DONE (uo_out[3]) seperti host sungguhan."""
    for _ in range(limit):
        if bus.pins() & ST_DONE:
            return
        await ClockCycles(bus.dut.clk, 1)
    raise AssertionError("pin DONE tidak pernah naik")


async def _time_of_rise(signal):
    await RisingEdge(signal)
    return now_us()


async def mac(bus, nonce, enter_mode=True, start_hold=1):
    """Satu MAC: (masuk mode Ascon), tulis nonce, START, tunggu DONE, baca tag.
    Mengembalikan (tag, siklus_hitung). Siklus hitung = tepi START sampai DONE naik."""
    if enter_mode:
        await bus.write(ADDR_CTRL, CTRL_MODE)
    for i, b in enumerate(nonce):
        await bus.write(ADDR_WIN + i, b)
    watcher = cocotb.start_soon(_time_of_rise(bus.dut.user_project.done))
    t_start = await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START, hold=start_hold)
    await wait_done(bus)
    t_done = await watcher
    tag = bytes([await bus.read(ADDR_WIN + i) for i in range(16)])
    return tag, cycles(t_start, t_done)


def load_kat_mac():
    path = os.path.join(REF, "kat", "LWC_AEAD_KAT_128_128.txt")
    entries = segel_model.load_kat(path)
    return [e for e in entries if e["PT"] == "" and e["AD"] == ""]


# ---------------------------------------------------------------------------
# Fungsi dasar
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_reset_status_version(dut):
    """Sesudah reset: semua pin status 0, STATUS = 0, VERSION = 0xA1."""
    bus = await init(dut)
    assert bus.pins() == 0
    assert await bus.read(ADDR_CTRL) == 0
    assert await bus.read(ADDR_VERSION) == 0xA1


@cocotb.test()
async def test_mac_kat(dut):
    """MAC lewat bus = KAT resmi Ascon-AEAD128 (PT dan AD kosong)."""
    bus = await init(dut)
    kats = load_kat_mac()
    assert kats, "KAT dengan PT & AD kosong tidak ditemukan"
    for e in kats:
        key, nonce = bytes.fromhex(e["Key"]), bytes.fromhex(e["Nonce"])
        await load_key(bus, key)
        tag, n = await mac(bus, nonce)
        dut._log.info("KAT Count %s: tag %s (%d siklus hitung)", e["Count"], tag.hex().upper(), n)
        assert tag.hex().upper() == e["CT"], f"KAT Count {e['Count']} gagal"
        assert n == 27
    MEAS["kat_passed"] = [e["Count"] for e in kats]
    save_measurements()


@cocotb.test()
async def test_mac_random_vs_pyascon(dut):
    """MAC untuk kunci/nonce acak = pyascon; pembaca bisa memverifikasi; tantangan diubah ditolak."""
    bus = await init(dut)
    rng = random.Random(4102026)
    n_ok, compute = 0, set()
    for k in range(8):                       # 8 kunci
        key = bytes(rng.getrandbits(8) for _ in range(16))
        await load_key(bus, key)
        first = True
        for _ in range(6):                   # 6 tantangan per kunci
            nonce = bytes(rng.getrandbits(8) for _ in range(16))
            tag, n = await mac(bus, nonce, enter_mode=first)
            first = False
            assert tag == ref_tag(key, nonce), "tag RTL != pyascon"
            # sisi pembaca (server Peruri): verifikasi berhasil, tantangan lain ditolak
            assert ascon.ascon_decrypt(key, nonce, b"", tag) == b""
            other = bytes([nonce[0] ^ 1]) + nonce[1:]
            assert ascon.ascon_decrypt(key, other, b"", tag) is None
            st = bus.pins()
            assert st == (ST_DONE | ST_MODE | ST_KEYV), f"status sesudah MAC = {st:#x}"
            compute.add(n)
            n_ok += 1
    dut._log.info("%d MAC acak cocok dengan pyascon; siklus hitung: %s", n_ok, sorted(compute))
    assert compute == {27}
    MEAS["random_macs_vs_pyascon"] = n_ok
    save_measurements()


# ---------------------------------------------------------------------------
# Uji keamanan S1..S7 (tabel Security Design di README.md)
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_s1_key_write_only(dut):
    """S1: kunci tersimpan (cek internal) tetapi alamat 40..55 selalu terbaca 0 di kedua mode."""
    bus = await init(dut)
    key = bytes(range(0xA0, 0xB0))
    await load_key(bus, key)
    assert int(dut.dbg_key.value) == int.from_bytes(key, "little"), "kunci tidak tersimpan"
    assert bus.pins() & ST_KEYV
    for mode in (0x00, CTRL_MODE):
        await bus.write(ADDR_CTRL, mode)
        for a in range(ADDR_KEY, ADDR_KEY + 16):
            assert await bus.read(a) == 0, f"kunci terbaca di alamat {a}"


@cocotb.test()
async def test_s2_state_read_locked(dut):
    """S2: di mode Ascon alamat 0..23 selalu 0; 24..39 terbaca 0 selama BUSY; sesudah DONE = tag."""
    bus = await init(dut)
    rng = random.Random(22)
    key = bytes(rng.getrandbits(8) for _ in range(16))
    nonce = bytes(rng.getrandbits(8) for _ in range(16))
    await load_key(bus, key)
    await bus.write(ADDR_CTRL, CTRL_MODE)
    for a in range(0, 24):
        await bus.write(a, 0xA5)             # tulisan sampah ke x0..x2: harus diabaikan
    for i, b in enumerate(nonce):
        await bus.write(ADDR_WIN + i, b)
    assert all([await bus.read(a) == 0 for a in range(0, 24)])
    assert bytes([await bus.read(ADDR_WIN + i) for i in range(16)]) == nonce  # nonce publik, boleh

    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START)
    # 10 pembacaan berikut terjadi pada tepi ke-4..22 sesudah START, jadi pasti selama BUSY (27 siklus)
    during = [await bus.read(ADDR_WIN + i) for i in range(8)]
    status_during = await bus.read(ADDR_CTRL)
    x0_during = await bus.read(0)
    assert status_during & ST_BUSY, "pembacaan uji tidak terjadi selama BUSY"
    assert during == [0] * 8, f"state terbaca selama BUSY: {during}"
    assert x0_during == 0

    await wait_done(bus)
    assert all([await bus.read(a) == 0 for a in range(0, 24)]), "x0..x2 terbaca sesudah DONE"
    tag = bytes([await bus.read(ADDR_WIN + i) for i in range(16)])
    assert tag == ref_tag(key, nonce), "tag salah (tulisan sampah ke 0..23 ikut terpakai?)"


@cocotb.test()
async def test_s3_zeroization(dut):
    """S3: x0..x2 nol sesudah TAG; ganti mode dan CLEAR menolkan state."""
    bus = await init(dut)
    rng = random.Random(33)
    key = bytes(rng.getrandbits(8) for _ in range(16))
    nonce = bytes(rng.getrandbits(8) for _ in range(16))
    await load_key(bus, key)
    tag, _ = await mac(bus, nonce)
    assert tag == ref_tag(key, nonce)
    for name in ("dbg_x0", "dbg_x1", "dbg_x2"):
        assert int(getattr(dut, name).value) == 0, f"{name} tidak dinolkan sesudah TAG"

    # ganti ke mode SHA: semua register harus 0 (tag dan sisa state hilang)
    await bus.write(ADDR_CTRL, 0x00)
    assert bus.pins() == ST_KEYV, "sesudah ganti mode: hanya KEY_VALID yang tersisa"
    assert all([await bus.read32(a) == 0 for a in range(0, 40, 4)])

    # CLEAR di mode Ascon menghapus nonce
    await bus.write(ADDR_CTRL, CTRL_MODE)
    for i, b in enumerate(nonce):
        await bus.write(ADDR_WIN + i, b)
    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_CLEAR)
    assert all([await bus.read(ADDR_WIN + i) == 0 for i in range(16)])
    for name in ("dbg_x0", "dbg_x1", "dbg_x2", "dbg_x3", "dbg_x4"):
        assert int(getattr(dut, name).value) == 0


@cocotb.test()
async def test_s4_key_zeroization(dut):
    """S4: KEY_CLEAR dan reset menghapus kunci; START sesudahnya ditolak."""
    bus = await init(dut)
    key = bytes(range(1, 17))
    await load_key(bus, key)
    assert bus.pins() & ST_KEYV
    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_KEYCLR)
    assert int(dut.dbg_key.value) == 0, "KEY_CLEAR tidak menghapus kunci"
    assert not bus.pins() & ST_KEYV
    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START)
    assert bus.pins() == (ST_ERR | ST_MODE), "START tanpa kunci harus ERR, tidak BUSY"

    await load_key(bus, key)
    assert int(dut.dbg_key.value) != 0
    await pulse_reset(bus)
    assert int(dut.dbg_key.value) == 0, "reset tidak menghapus kunci"
    assert bus.pins() == 0


@cocotb.test()
async def test_s5_constant_time(dut):
    """S5: siklus hitung selalu sama untuk kunci/nonce ekstrem dan acak."""
    bus = await init(dut)
    rng = random.Random(55)
    cases = [(bytes(16), bytes(16)), (b"\xff" * 16, b"\xff" * 16),
             (bytes(16), b"\xff" * 16), (b"\xff" * 16, bytes(16))]
    cases += [(bytes(rng.getrandbits(8) for _ in range(16)),
               bytes(rng.getrandbits(8) for _ in range(16))) for _ in range(12)]
    seen = []
    for key, nonce in cases:
        await load_key(bus, key)
        tag, n = await mac(bus, nonce)
        assert tag == ref_tag(key, nonce)
        seen.append(n)
    dut._log.info("siklus hitung untuk %d pasangan kunci/nonce: %s", len(seen), sorted(set(seen)))
    assert set(seen) == {27}
    MEAS["compute_cycles_per_mac"] = 27
    MEAS["constant_time_cases"] = len(seen)
    save_measurements()


@cocotb.test()
async def test_s6_edge_detect(dut):
    """S6: io_clk ditahan beberapa siklus tetap dihitung SATU aksi (bug baseline diperbaiki)."""
    bus = await init(dut)
    # (a) ronde SHA dengan io_clk ditahan 2 siklus (skenario test_ioclk_held_two_cycles baseline)
    w, k = 0x13371337, SHA_K[0]
    for i in range(8):
        await bus.write32(i * 4, H0[i])
    await bus.write32(32, w)
    await bus.write32(36, k)
    await bus.write(ADDR_SHA, 0, hold=2)
    state = [await bus.read32(i * 4) for i in range(8)]
    one = sha_round_model(list(H0), w, k)
    assert state == one, "io_clk ditahan 2 siklus tidak menghasilkan tepat 1 ronde"
    MEAS["ioclk_hold_2_cycles_rounds_executed"] = 1

    # (b) START dengan io_clk ditahan 5 siklus: tepat satu MAC, tidak ada ERR
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    await load_key(bus, key)
    tag, n = await mac(bus, nonce, start_hold=5)
    assert tag == ref_tag(key, nonce)
    assert not bus.pins() & ST_ERR, "START terpicu lebih dari sekali"
    save_measurements()


@cocotb.test()
async def test_s7_illegal_commands(dut):
    """S7: START tanpa kunci, ronde SHA di mode Ascon, dan tulisan selama BUSY ditolak (ERR)."""
    bus = await init(dut)
    # (a) START tanpa kunci
    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START)
    assert bus.pins() == (ST_ERR | ST_MODE)
    # (b) ronde SHA di mode Ascon ditolak, nonce tidak berubah
    nonce = bytes(range(0x30, 0x40))
    for i, b in enumerate(nonce):
        await bus.write(ADDR_WIN + i, b)
    await bus.write(ADDR_CTRL, CTRL_MODE)    # hapus ERR
    assert not bus.pins() & ST_ERR
    await bus.write(ADDR_SHA, 0)
    assert bus.pins() & ST_ERR
    assert bytes([await bus.read(ADDR_WIN + i) for i in range(16)]) == nonce
    # (c) tulisan selama BUSY: coba ganti mode, ganti kunci, ganti nonce, ronde SHA
    key = bytes(range(0x50, 0x60))
    await load_key(bus, key)
    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START)
    await bus.write(ADDR_CTRL, 0x00)         # ganti ke mode SHA -> harus diabaikan
    await bus.write(ADDR_KEY, 0xEE)          # ganti byte kunci -> diabaikan
    await bus.write(ADDR_WIN, 0xEE)          # ganti nonce -> diabaikan
    await bus.write(ADDR_SHA, 0)             # ronde SHA -> diabaikan
    await wait_done(bus)
    st = bus.pins()
    assert st & ST_ERR and st & ST_MODE and st & ST_DONE, f"status = {st:#x}"
    tag = bytes([await bus.read(ADDR_WIN + i) for i in range(16)])
    assert tag == ref_tag(key, nonce), "tulisan selama BUSY mengubah hasil"
    assert int(dut.dbg_key.value) == int.from_bytes(key, "little")
    # (d) KEY_CLEAR + START dalam satu tulisan -> ERR, kunci terhapus
    await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START | CTRL_KEYCLR)
    st = bus.pins()
    assert st & ST_ERR and not st & ST_KEYV and not st & ST_BUSY


# ---------------------------------------------------------------------------
# Kompatibilitas dan pengukuran
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_sha_after_ascon(dut):
    """Sesudah MAC Ascon, mode SHA-256 baseline tetap menghasilkan hash FIPS 180-2 yang benar."""
    bus = await init(dut)
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    await load_key(bus, key)
    tag, _ = await mac(bus, nonce)
    assert tag == ref_tag(key, nonce)
    await bus.write(ADDR_CTRL, 0x00)
    for message, expected_hex in NIST_VECTORS:
        padded = pad(message)
        h = list(H0)
        for c in range(0, len(padded), 64):
            w = schedule(padded[c:c + 64])
            for i in range(8):
                await bus.write32(i * 4, h[i])
            for i in range(64):
                await bus.write32(32, w[i])
                await bus.write32(36, SHA_K[i])
                await bus.write(ADDR_SHA, 0)
            state = [await bus.read32(i * 4) for i in range(8)]
            h = [(h[i] + state[i]) & 0xFFFFFFFF for i in range(8)]
        assert struct.pack("!8I", *h).hex() == expected_hex


@cocotb.test()
async def test_cycle_budget(dut):
    """Ukur siklus bus untuk muat kunci dan satu MAC lengkap (bandingkan dengan model: 97)."""
    bus = await init(dut)
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    await bus.set_mode(MODE_WRITE)
    t0 = now_us()
    await load_key(bus, key)
    t_key = now_us()
    await bus.write(ADDR_CTRL, CTRL_MODE)
    t_mode = now_us()
    # --- satu MAC, kunci sudah dimuat ---
    for i, b in enumerate(nonce):
        await bus.write(ADDR_WIN + i, b)
    t_nonce = now_us()
    watcher = cocotb.start_soon(_time_of_rise(dut.user_project.done))
    t_start = await bus.write(ADDR_CTRL, CTRL_MODE | CTRL_START)
    await wait_done(bus)
    t_done_seen = now_us()
    t_done = await watcher
    await bus.set_mode(MODE_READ)
    t_rd = now_us()
    tag = bytes([await bus.read(ADDR_WIN + i) for i in range(16)])
    t_tag = now_us()
    await bus.set_mode(MODE_WRITE)
    t_end = now_us()
    assert tag == ref_tag(key, nonce)
    budget = {
        "muat kunci (sekali sesudah reset)": cycles(t0, t_key),
        "masuk mode Ascon (sekali)": cycles(t_key, t_mode),
        "tulis nonce": cycles(t_mode, t_nonce),
        "tulis START sampai DONE terlihat host": cycles(t_nonce, t_done_seen),
        "ganti arah tulis->baca": cycles(t_done_seen, t_rd),
        "baca tag": cycles(t_rd, t_tag),
        "ganti arah baca->tulis": cycles(t_tag, t_end),
    }
    per_mac = cycles(t_mode, t_end)
    dut._log.info("anggaran siklus: %s; total per MAC (kunci sudah dimuat) = %d", budget, per_mac)
    MEAS["compute_cycles_start_to_done"] = cycles(t_start, t_done)
    MEAS["bus_cycles_breakdown"] = budget
    MEAS["bus_cycles_per_mac_key_loaded"] = per_mac
    save_measurements()
