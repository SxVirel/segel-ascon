# SPDX-FileCopyrightText: Copyright (c) 2024 xenia dragon
# SPDX-License-Identifier: Apache-2.0

import hashlib
import struct

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles


IO_RWSEL = 0b0100_0000
IO_CLK = 0b1000_0000

MODE_READ = 1
MODE_WRITE = 2

class TestMeta:
    def __init__(self):
        self.mode = None


async def io_write(dut, meta: TestMeta, addr: int, word: int) -> None:
    assert addr & 0b11 == 0

    if meta.mode != MODE_WRITE:
        dut.ui_in.value = 0
        await ClockCycles(dut.clk, 1)
        meta.mode = MODE_WRITE
        assert (dut.uo_out.value >> 1) & 1 == 0
        assert dut.uio_oe.value == 0x00
        await ClockCycles(dut.clk, 1)

    for i in range(4):
        # dut._log.info("writing %s=%s",
        #               f"{addr | i:02x}",
        #               f"{(word >> (i*8)) & 0xFF:08b}")

        dut.uio_in.value = (word >> (i*8)) & 0xFF
        dut.ui_in.value = IO_CLK | addr | i
        await ClockCycles(dut.clk, 1)
        dut.uio_in.value = (word >> (i*8)) & 0xFF
        dut.ui_in.value = addr | i
        await ClockCycles(dut.clk, 1)


async def io_read(dut, meta: TestMeta, addr: int) -> int:
    assert addr & 0b11 == 0

    if meta.mode != MODE_READ:
        dut.ui_in.value = IO_RWSEL
        await ClockCycles(dut.clk, 1)
        meta.mode = MODE_READ
        assert (dut.uo_out.value >> 1) & 1 == 1
        assert dut.uio_oe.value == 0xff
        await ClockCycles(dut.clk, 1)

    word = 0
    for i in range(4):
        dut.ui_in.value = IO_CLK | IO_RWSEL | addr | i
        await ClockCycles(dut.clk, 1)
        dut.ui_in.value = IO_RWSEL | addr | i
        await ClockCycles(dut.clk, 1)
        word |= (dut.uio_out.value & 0xFF) << (i*8)

        # dut._log.info("reading %s=%s",
        #               f"{addr | i:02x}",
        #               dut.uio_out.value)

    return word


async def io_trigger(dut, meta: TestMeta) -> None:
    if meta.mode != MODE_WRITE:
        dut.ui_in.value = 0
        await ClockCycles(dut.clk, 1)
        meta.mode = MODE_WRITE
        assert (dut.uo_out.value >> 1) & 1 == 0
        assert dut.uio_oe.value == 0x00
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0
    dut.ui_in.value = IO_CLK | 63
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0
    dut.ui_in.value = 63
    await ClockCycles(dut.clk, 1)



async def test_init(dut):
    meta = TestMeta()

    dut._log.info("Start")

    # Set the clock period to 10 us (100 KHz)
    clock = Clock(dut.clk, 10, units="us")
    cocotb.start_soon(clock.start())

    # Reset
    dut._log.info("Reset")
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1

    return meta


@cocotb.test()
async def test_registers(dut):
    meta = await test_init(dut)
    dut._log.info("Test registers")

    for addr in range(0, 40, 4):
        dut._log.info("Test register %s", addr)
        for val in [0x1312621, 0, 0xffffffff, 0x13371337, 0x55aa9966]:
            await io_write(dut, meta, addr, val)
            rval = await io_read(dut, meta, addr)
            assert val == rval


K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def _rotr(x, y):
    return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF

def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def _ch(x, y, z):
    return (x & y) ^ ((~x) & z)


@cocotb.test()
async def test_sha_round(dut):
    meta = await test_init(dut)
    dut._log.info("Test SHA-2 compression cycle")
    for w in [0x1312621, 0, 0xffffffff, 0x13371337, 0x55aa9966]:
        for i in range(8):
            await io_write(dut, meta, i*4, H[i])
        await io_write(dut, meta, 32, w)
        await io_write(dut, meta, 36, K[0])

        await io_trigger(dut, meta)

        a, b, c, d, e, f, g, h = H
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = s0 + _maj(a, b, c)
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = h + s1 + _ch(e, f, g) + K[0] + w

        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

        expected = [a, b, c, d, e, f, g, h]

        for i in range(8):
            actual = await io_read(dut, meta, i*4)
            assert actual == expected[i]


async def test_one_sha_full(dut, meta, message: bytes) -> None:
    reference_hash = hashlib.sha256(message).digest()

    mdi = len(message) & 0x3F
    length = struct.pack('!Q', len(message) << 3)

    if mdi < 56:
        padlen = 55 - mdi
    else:
        padlen = 119 - mdi

    message = message + b'\x80' + (b'\x00' * padlen) + length

    assert len(message) % 64 == 0

    h = list(H)

    for chunk_idx in range(0, len(message), 64):
        chunk = message[chunk_idx:chunk_idx+64]

        for i in range(8):
            await io_write(dut, meta, i*4, h[i])

        w = [0] * 64
        w[0:16] = struct.unpack('!16L', chunk)
        for i in range(16, 64):
            s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

        for i in range(64):
            await io_write(dut, meta, 32, w[i])
            await io_write(dut, meta, 36, K[i])

            await io_trigger(dut, meta)

        for i in range(8):
            h[i] = (h[i] + (await io_read(dut, meta, i*4))) & 0xFFFFFFFF

    result = struct.pack("!IIIIIIII", *h)
    assert result == reference_hash

@cocotb.test()
async def test_sha_full(dut):
    meta = await test_init(dut)
    dut._log.info("Test SHA-2 full hash")

    await test_one_sha_full(dut, meta, b"")
    await test_one_sha_full(dut, meta, b"message digest")
    await test_one_sha_full(dut, meta, b"trans rights")
    await test_one_sha_full(dut, meta, b"abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab")
