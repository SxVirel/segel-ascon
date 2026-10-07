<!---
This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

Segel Ascon extends the TT07 "tiny sha256" baseline (#0718). The SHA-256 round mode is unchanged.
A second mode computes an Ascon-AEAD128 tag (NIST SP 800-232) with empty associated data and empty
plaintext, so the chip answers a 16-byte challenge (used as the nonce) with a 128-bit tag that only
the holder of the key can produce. The 320-bit Ascon state reuses the baseline's 10 x 32-bit register
file. One Ascon round is computed per clock cycle; a tag takes 27 clock cycles.

Security features: the 128-bit key is write-only, state registers cannot be read while in Ascon mode
(except the nonce/tag window when not busy), state is zeroized on mode change, CLEAR, reset and at the
end of each tag, and the bus strobe is edge-detected.

Register map: 0-39 register file (Ascon mode: 24-39 = nonce in / tag out), 40-55 key (write-only),
56 CTRL (write) / STATUS (read), 57 VERSION (0xA1), 63 SHA-256 round command (SHA mode only).
CTRL bits: 0 MODE, 1 START, 2 CLEAR, 3 KEY_CLEAR.

## How to test

1. Write the key bytes to addresses 40..55.
2. Write 0x01 to CTRL (enter Ascon mode).
3. Write the 16-byte challenge to addresses 24..39.
4. Write 0x03 to CTRL (MODE | START) and wait for uo[3] (DONE).
5. Read the tag from addresses 24..39 and compare with Ascon-AEAD128(K, N, "", "").

Each bus access: set address (ui[5:0]), direction (ui[6]) and data, raise ui[7] for one clock, lower it
for one clock.

## External hardware

None. A microcontroller (for example the RP2040 on the Tiny Tapeout demo board) acts as the host/reader.
