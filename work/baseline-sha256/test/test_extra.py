# SPDX-License-Identifier: Apache-2.0
# Additional tests for the TT07 #0718 "tiny sha256" baseline (xeniarose/tt07-sha256).
# Bus helpers mirror test.py from the original repo so this file is self-contained.

import hashlib
import json
import struct

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles
from cocotb.utils import get_sim_time

CLK_PERIOD_US = 10
IO_RWSEL = 0b0100_0000
IO_CLK = 0b1000_0000
MODE_READ = 1
MODE_WRITE = 2

K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# FIPS 180-2 Appendix B example vectors (one-block and two-block messages).
NIST_VECTORS = [
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]

MEASUREMENTS = {}


def _rotr(x, y):
    return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF


def _round(state, w, k):
    a, b, c, d, e, f, g, h = state
    s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
    t2 = s0 + ((a & b) ^ (a & c) ^ (b & c))
    s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
    t1 = h + s1 + ((e & f) ^ ((~e) & g)) + k + w
    return [(t1 + t2) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g]


class Bus:
    def __init__(self, dut):
        self.dut = dut
        self.mode = None

    async def _set_mode(self, mode):
        if self.mode != mode:
            self.dut.ui_in.value = IO_RWSEL if mode == MODE_READ else 0
            await ClockCycles(self.dut.clk, 2)
            self.mode = mode

    async def write(self, addr, word):
        await self._set_mode(MODE_WRITE)
        for i in range(4):
            self.dut.uio_in.value = (word >> (i * 8)) & 0xFF
            self.dut.ui_in.value = IO_CLK | addr | i
            await ClockCycles(self.dut.clk, 1)
            self.dut.ui_in.value = addr | i
            await ClockCycles(self.dut.clk, 1)

    async def read(self, addr):
        await self._set_mode(MODE_READ)
        word = 0
        for i in range(4):
            self.dut.ui_in.value = IO_CLK | IO_RWSEL | addr | i
            await ClockCycles(self.dut.clk, 1)
            self.dut.ui_in.value = IO_RWSEL | addr | i
            await ClockCycles(self.dut.clk, 1)
            word |= (self.dut.uio_out.value.integer & 0xFF) << (i * 8)
        return word

    async def trigger(self, hold_cycles=1):
        await self._set_mode(MODE_WRITE)
        self.dut.uio_in.value = 0
        self.dut.ui_in.value = IO_CLK | 63
        await ClockCycles(self.dut.clk, hold_cycles)
        self.dut.ui_in.value = 63
        await ClockCycles(self.dut.clk, 1)


async def init(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_US, units="us").start())
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    return Bus(dut)


def cycles_since(t0_us):
    return round((get_sim_time(units="us") - t0_us) / CLK_PERIOD_US)


def pad(message):
    mdi = len(message) & 0x3F
    padlen = (55 - mdi) if mdi < 56 else (119 - mdi)
    return message + b"\x80" + b"\x00" * padlen + struct.pack("!Q", len(message) << 3)


def schedule(chunk):
    w = list(struct.unpack("!16L", chunk)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
    return w


def save_measurements():
    with open("measurements.json", "w") as f:
        json.dump(MEASUREMENTS, f, indent=2)


@cocotb.test()
async def test_nist_vectors_and_cycle_count(dut):
    """Hash the FIPS 180-2 example vectors on the baseline and count bus clock cycles per block."""
    bus = await init(dut)
    per_block = []
    for message, expected_hex in NIST_VECTORS:
        assert hashlib.sha256(message).hexdigest() == expected_hex
        padded = pad(message)
        h = list(H0)
        for chunk_idx in range(0, len(padded), 64):
            w = schedule(padded[chunk_idx:chunk_idx + 64])
            t0 = get_sim_time(units="us")
            for i in range(8):
                await bus.write(i * 4, h[i])
            for i in range(64):
                await bus.write(32, w[i])
                await bus.write(36, K[i])
                await bus.trigger()
            state = [await bus.read(i * 4) for i in range(8)]
            per_block.append(cycles_since(t0))
            h = [(h[i] + state[i]) & 0xFFFFFFFF for i in range(8)]
        digest = struct.pack("!8I", *h).hex()
        dut._log.info("SHA-256(%r) = %s", message, digest)
        assert digest == expected_hex
    MEASUREMENTS["nist_vectors_passed"] = [m.decode() for m, _ in NIST_VECTORS]
    MEASUREMENTS["bus_cycles_per_block"] = per_block
    MEASUREMENTS["compute_cycles_per_block"] = 64
    save_measurements()
    dut._log.info("Bus clock cycles per 64-byte block: %s", per_block)


@cocotb.test()
async def test_ioclk_held_two_cycles(dut):
    """Hold io_clk high for 2 clk cycles on the round command and report how many rounds executed."""
    bus = await init(dut)
    w, k = 0x13371337, K[0]
    for i in range(8):
        await bus.write(i * 4, H0[i])
    await bus.write(32, w)
    await bus.write(36, k)
    await bus.trigger(hold_cycles=2)
    state = [await bus.read(i * 4) for i in range(8)]

    one = _round(list(H0), w, k)
    two = _round(one, w, k)
    rounds = 1 if state == one else 2 if state == two else None
    dut._log.info("io_clk held for 2 clk cycles -> rounds executed: %s", rounds)
    MEASUREMENTS["ioclk_hold_2_cycles_rounds_executed"] = rounds
    save_measurements()
    assert rounds is not None, "state matches neither 1 nor 2 rounds"
