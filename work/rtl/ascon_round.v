/*
 * Segel Ascon — satu ronde permutasi Ascon-p (NIST SP 800-232, bagian 3).
 *
 * Murni kombinasional: state 320 bit (x0..x4, masing-masing 64 bit) masuk,
 * state sesudah 1 ronde keluar pada siklus yang sama (varian R1).
 *
 * Urutan langkah sama persis dengan ascon_round() di work/ref/segel_model.py:
 *   1. tambah konstanta ronde ke x2
 *   2. lapisan substitusi: 64 S-box 5 bit, ditulis "bitsliced" (64 kolom sekaligus)
 *   3. lapisan difusi linear: tiap word di-XOR dengan dua rotasinya
 *
 * Konvensi: rotr(x, n) = {x[n-1:0], x[63:n]} (putar ke kanan n bit).
 */

`default_nettype none

module ascon_round (
    input  wire [63:0] x0_i,
    input  wire [63:0] x1_i,
    input  wire [63:0] x2_i,
    input  wire [63:0] x3_i,
    input  wire [63:0] x4_i,
    input  wire [7:0]  rc,      // konstanta ronde, mis. 0xF0 untuk ronde pertama p12
    output wire [63:0] x0_o,
    output wire [63:0] x1_o,
    output wire [63:0] x2_o,
    output wire [63:0] x3_o,
    output wire [63:0] x4_o
);

  // 1. Penambahan konstanta ronde (hanya 8 bit terbawah x2)
  wire [63:0] x2_c = x2_i ^ {56'h0, rc};

  // 2. Lapisan substitusi (S-box 5 bit Ascon dalam bentuk bitsliced)
  //    a) campur awal
  wire [63:0] a0 = x0_i ^ x4_i;
  wire [63:0] a1 = x1_i;
  wire [63:0] a2 = x2_c ^ x1_i;
  wire [63:0] a3 = x3_i;
  wire [63:0] a4 = x4_i ^ x3_i;
  //    b) inti non-linear (chi): t_i = NOT(a_i) AND a_{i+1}
  wire [63:0] t0 = ~a0 & a1;
  wire [63:0] t1 = ~a1 & a2;
  wire [63:0] t2 = ~a2 & a3;
  wire [63:0] t3 = ~a3 & a4;
  wire [63:0] t4 = ~a4 & a0;
  wire [63:0] b0 = a0 ^ t1;
  wire [63:0] b1 = a1 ^ t2;
  wire [63:0] b2 = a2 ^ t3;
  wire [63:0] b3 = a3 ^ t4;
  wire [63:0] b4 = a4 ^ t0;
  //    c) campur akhir
  wire [63:0] s0 = b0 ^ b4;
  wire [63:0] s1 = b1 ^ b0;
  wire [63:0] s2 = ~b2;
  wire [63:0] s3 = b3 ^ b2;
  wire [63:0] s4 = b4;

  // 3. Lapisan difusi linear: x_i ^= rotr(x_i, r1) ^ rotr(x_i, r2)
  assign x0_o = s0 ^ {s0[18:0], s0[63:19]} ^ {s0[27:0], s0[63:28]};  // 19, 28
  assign x1_o = s1 ^ {s1[60:0], s1[63:61]} ^ {s1[38:0], s1[63:39]};  // 61, 39
  assign x2_o = s2 ^ {s2[0],    s2[63:1]}  ^ {s2[5:0],  s2[63:6]};   //  1,  6
  assign x3_o = s3 ^ {s3[9:0],  s3[63:10]} ^ {s3[16:0], s3[63:17]};  // 10, 17
  assign x4_o = s4 ^ {s4[6:0],  s4[63:7]}  ^ {s4[40:0], s4[63:41]};  //  7, 41

endmodule
