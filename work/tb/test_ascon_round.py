# SPDX-License-Identifier: Apache-2.0
"""
Uji unit ascon_round.v (satu ronde Ascon-p, kombinasional).

Acuan benar:
  - ascon_round() di work/ref/segel_model.py (model per langkah, sudah dicek ke KAT);
  - ascon_permutation() dari pyascon (implementasi referensi resmi, CC0) untuk 12 ronde berturut-turut.
"""
import os
import random
import sys

import cocotb
from cocotb.triggers import Timer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ref"))
import segel_model as model  # noqa: E402  (ikut menambahkan pyascon ke sys.path)
import ascon  # noqa: E402

MASK64 = (1 << 64) - 1


async def one_round(dut, x, rc):
    for i in range(5):
        getattr(dut, f"x{i}_i").value = x[i]
    dut.rc.value = rc
    await Timer(1, units="ns")
    return [int(getattr(dut, f"x{i}_o").value) for i in range(5)]


@cocotb.test()
async def test_round_vs_model(dut):
    """1 ronde RTL = 1 ronde model, untuk 12 konstanta ronde dan state acak/ekstrem."""
    rng = random.Random(20261004)
    states = [[0] * 5, [MASK64] * 5, [1 << 63, 1, 0x0123456789ABCDEF, 0, MASK64]]
    states += [[rng.getrandbits(64) for _ in range(5)] for _ in range(300)]
    checked = 0
    for x in states:
        for r in range(12):
            c = model.round_constant(r)
            got = await one_round(dut, x, c)
            exp = model.ascon_round(x, c)
            assert got == exp, f"ronde {r} salah untuk state {[hex(v) for v in x]}"
            checked += 1
    dut._log.info("ascon_round: %d kombinasi state x konstanta cocok dengan model", checked)


@cocotb.test()
async def test_p12_vs_pyascon(dut):
    """12 ronde RTL berurutan (0xF0 .. 0x4B) = ascon_permutation(S, 12) dari pyascon."""
    rng = random.Random(7)
    for _ in range(100):
        x = [rng.getrandbits(64) for _ in range(5)]
        s = list(x)
        for r in range(12):
            s = await one_round(dut, s, model.round_constant(r))
        ref = list(x)
        ascon.ascon_permutation(ref, 12)
        assert s == ref, "p12 RTL tidak sama dengan pyascon"
    dut._log.info("p12 (12 ronde RTL) = pyascon untuk 100 state acak")
