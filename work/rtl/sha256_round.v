/*
 * Segel Ascon — fungsi ronde SHA-256 milik baseline TT07 #0718 (xeniarose/tt07-sha256).
 *
 * Rumusnya disalin TANPA perubahan dari project.v baseline (baris 63–70 dan 94/98):
 * hanya dipindah ke modul sendiri agar mudah dibaca. Register A..H tidak ada di sini;
 * modul ini hanya menghitung nilai baru untuk A dan E. Sisanya bergeser (B<=A, C<=B, ...).
 *
 * SPDX-FileCopyrightText: Copyright (c) 2024 xenia dragon (rumus asli)
 * SPDX-License-Identifier: Apache-2.0
 */

`default_nettype none

module sha256_round (
    input  wire [31:0] a,
    input  wire [31:0] b,
    input  wire [31:0] c,
    input  wire [31:0] d,
    input  wire [31:0] e,
    input  wire [31:0] f,
    input  wire [31:0] g,
    input  wire [31:0] h,
    input  wire [31:0] w,      // word jadwal pesan (dihitung host)
    input  wire [31:0] k,      // konstanta ronde (diberikan host)
    output wire [31:0] a_new,
    output wire [31:0] e_new
);

  wire [31:0] s1    = {e[5:0], e[31:6]} ^ {e[10:0], e[31:11]} ^ {e[24:0], e[31:25]};
  wire [31:0] ch    = (e & f) ^ ((~e) & g);
  wire [31:0] temp1 = h + s1 + ch + k + w;
  wire [31:0] s0    = {a[1:0], a[31:2]} ^ {a[12:0], a[31:13]} ^ {a[21:0], a[31:22]};
  wire [31:0] maj   = (a & b) ^ (a & c) ^ (b & c);
  wire [31:0] temp2 = s0 + maj;

  assign a_new = temp1 + temp2;
  assign e_new = d + temp1;

endmodule
