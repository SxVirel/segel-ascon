/*
 * Segel Ascon — top level Tiny Tapeout (desain utama, varian ronde R1).
 *
 * Titik awal: baseline TT07 #0718 "tiny sha256" (github.com/xeniarose/tt07-sha256,
 * Apache-2.0, salinan di work/baseline-sha256/src/project.v). Mode SHA-256 baseline
 * tetap ada dan tetap memakai protokol bus yang sama. Yang ditambahkan:
 *   - mode Ascon: MAC Ascon-AEAD128 (NIST SP 800-232) dengan AD dan plaintext kosong,
 *     state 320 bit-nya MEMAKAI register file baseline 10 x 32 bit (berbagi register);
 *   - kunci 128 bit tulis-saja, pembacaan state dikunci di mode Ascon, zeroization;
 *   - deteksi tepi io_clk (perbaikan bug hitungan ganda baseline);
 *   - pin status BUSY, DONE, MODE, KEY_VALID, ERR.
 * Spesifikasi ringkas ada di README.md. Nomor S1..S7 = mekanisme
 * keamanan (tabel Security Design di README.md), dan masing-masing punya uji di work/tb/test_segel.py.
 *
 * Peta isi file ini:
 *   1. bus_if      antarmuka bus + deteksi tepi io_clk
 *   2. access_ctrl dekoder alamat dan kebijakan baca/tulis
 *   3. regfile     register file baseline 10 x 32 bit + key_reg 128 bit
 *   4. state Ascon dan ascon_round (lihat ascon_round.v)
 *   5. mac_fsm     urutan LOAD -> p12 -> MID -> p12 -> TAG (27 siklus)
 *   6. always block utama (semua register ditulis di sini)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

`default_nettype none

module tt_um_sxvirel_segel_ascon #(
    // 1 = desain utama: state Ascon memakai register file baseline.
    // 0 = KHUSUS PEMBANDING AREA: state Ascon di register 320 bit sendiri
    //     (fungsi sama persis; dipakai untuk mengukur penghematan berbagi register).
    parameter SHARED_STATE = 1
) (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // always 1 when the design is powered, so you can ignore it
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

  // ---------------------------------------------------------------------------
  // Konstanta
  // ---------------------------------------------------------------------------
  localparam [63:0] ASCON_IV = 64'h00001000808C0001;  // IV Ascon-AEAD128 (SP 800-232, Alg. 3)
  localparam [7:0]  VERSION  = 8'hA1;

  // Peta alamat (lihat README.md)
  localparam [5:0] ADDR_WIN_LO  = 6'd24;  // 24..39: jendela nonce/tag (register 6..9)
  localparam [5:0] ADDR_REG_END = 6'd40;  //  0..39: register file baseline
  localparam [5:0] ADDR_KEY_LO  = 6'd40;  // 40..55: kunci, tulis-saja
  localparam [5:0] ADDR_KEY_HI  = 6'd55;
  localparam [5:0] ADDR_CTRL    = 6'd56;  // tulis = CTRL, baca = STATUS
  localparam [5:0] ADDR_VERSION = 6'd57;
  localparam [5:0] ADDR_SHA     = 6'd63;  // perintah 1 ronde SHA-256 (baseline)

  // Bit register CTRL
  localparam CTRL_MODE   = 0;  // 0 = SHA, 1 = Ascon
  localparam CTRL_START  = 1;  // mulai MAC
  localparam CTRL_CLEAR  = 2;  // nolkan register 0..9 dan DONE
  localparam CTRL_KEYCLR = 3;  // nolkan kunci

  // Langkah FSM MAC
  localparam [2:0] S_IDLE = 3'd0;
  localparam [2:0] S_LOAD = 3'd1;  // x0 = IV, x1||x2 = K
  localparam [2:0] S_INIT = 3'd2;  // 12 ronde inisialisasi
  localparam [2:0] S_MID  = 3'd3;  // semua XOR antara dua p12 digabung
  localparam [2:0] S_FIN  = 3'd4;  // 12 ronde finalisasi
  localparam [2:0] S_TAG  = 3'd5;  // tag = x3||x4 ^ K, x0..x2 dinolkan

  // ---------------------------------------------------------------------------
  // 1. bus_if — protokol bus baseline + deteksi tepi io_clk
  // ---------------------------------------------------------------------------
  wire [5:0] io_addr = ui_in[5:0];
  wire       io_rd   = ui_in[6];   // 1 = host membaca (pin uio jadi output), 0 = host menulis
  wire       io_clk  = ui_in[7];

  reg  io_clk_q;                        // io_clk pada siklus sebelumnya
  wire io_strobe = io_clk & ~io_clk_q;  // S6: satu aksi per tepi naik, berapa lama pun io_clk ditahan
  wire bus_wr    = io_strobe & ~io_rd;
  wire bus_rd    = io_strobe &  io_rd;

  reg       io_ready;
  reg [7:0] io_out;

  reg mode_ascon;  // MODE      : 0 = SHA-256 (baseline), 1 = Ascon
  reg busy;        // BUSY      : MAC sedang dihitung
  reg done;        // DONE      : tag siap dibaca
  reg key_valid;   // KEY_VALID : 16 byte kunci sudah ditulis
  reg err;         // ERR       : perintah terakhir ditolak

  wire [7:0] status = {3'b000, err, key_valid, mode_ascon, done, busy};

  assign uo_out  = {1'b0, status[4:0], io_rd, io_ready};  // uo_out[6:2] = STATUS[4:0]
  assign uio_out = io_out;
  assign uio_oe  = {8{io_rd}};

  wire _unused = &{ena, 1'b0};

  // ---------------------------------------------------------------------------
  // 2. access_ctrl — dekoder alamat dan kebijakan akses
  // ---------------------------------------------------------------------------
  wire is_reg  = (io_addr <  ADDR_REG_END);
  wire is_win  = (io_addr >= ADDR_WIN_LO) & is_reg;
  wire is_key  = (io_addr >= ADDR_KEY_LO) & (io_addr <= ADDR_KEY_HI);
  wire is_ctrl = (io_addr == ADDR_CTRL);
  wire is_sha  = (io_addr == ADDR_SHA);

  wire       wr_ok    = bus_wr & ~busy;  // S7: semua tulisan selama BUSY ditolak
  wire       new_mode = uio_in[CTRL_MODE];
  // S3: ganti mode atau CLEAR menolkan seluruh state
  wire       zeroize  = wr_ok & is_ctrl & (uio_in[CTRL_CLEAR] | (new_mode != mode_ascon));
  // nonce dari host masuk ke jendela 24..39 (hanya di mode Ascon)
  wire       win_wr   = wr_ok & mode_ascon & is_win;
  wire [5:0] key_off  = io_addr - ADDR_KEY_LO;  // 40..55 -> 0..15

  // ---------------------------------------------------------------------------
  // 3. regfile (baseline) dan key_reg
  // ---------------------------------------------------------------------------
  reg [31:0] register_file [0:9];

  `define A_reg register_file[0]
  `define B_reg register_file[1]
  `define C_reg register_file[2]
  `define D_reg register_file[3]
  `define E_reg register_file[4]
  `define F_reg register_file[5]
  `define G_reg register_file[6]
  `define H_reg register_file[7]
  `define W_reg register_file[8]
  `define K_reg register_file[9]

  // byte register yang sedang dialamatkan (dipakai jalur baca)
  wire [31:0] rf_word = register_file[io_addr[5:2]];
  reg  [7:0]  rf_byte;
  always @(*) begin
    case (io_addr[1:0])
      2'd0:    rf_byte = rf_word[7:0];
      2'd1:    rf_byte = rf_word[15:8];
      2'd2:    rf_byte = rf_word[23:16];
      default: rf_byte = rf_word[31:24];
    endcase
  end

  // S1: kunci TULIS-SAJA. Tidak ada satu pun jalur dari register ini ke pin output.
  reg  [127:0] key;
  wire [63:0]  k0 = key[63:0];    // byte kunci 0..7  (little-endian, sesuai SP 800-232)
  wire [63:0]  k1 = key[127:64];  // byte kunci 8..15

  // Fungsi ronde SHA-256 baseline (rumus tidak diubah, lihat sha256_round.v)
  wire [31:0] sha_a, sha_e;
  sha256_round u_sha (
      .a(`A_reg), .b(`B_reg), .c(`C_reg), .d(`D_reg),
      .e(`E_reg), .f(`F_reg), .g(`G_reg), .h(`H_reg),
      .w(`W_reg), .k(`K_reg),
      .a_new(sha_a), .e_new(sha_e)
  );

  // ---------------------------------------------------------------------------
  // 4. State Ascon x0..x4 (5 x 64 bit) dan satu ronde Ascon-p
  // ---------------------------------------------------------------------------
  wire [63:0] x0, x1, x2, x3, x4;            // state sekarang
  reg  [63:0] x0_n, x1_n, x2_n, x3_n, x4_n;  // state sesudah langkah FSM berikutnya
  wire [7:0]  win_byte;                      // byte jendela nonce/tag untuk jalur baca

  reg  [2:0]  fsm;
  reg  [3:0]  rnd;                 // nomor ronde 0..11 di dalam p12
  wire [7:0]  rc = {~rnd, rnd};    // konstanta ronde p12: 0xF0, 0xE1, ..., 0x4B (tanpa ROM)

  wire [63:0] r0, r1, r2, r3, r4;  // state sesudah 1 ronde
  ascon_round u_ascon (
      .x0_i(x0), .x1_i(x1), .x2_i(x2), .x3_i(x3), .x4_i(x4), .rc(rc),
      .x0_o(r0), .x1_o(r1), .x2_o(r2), .x3_o(r3), .x4_o(r4)
  );

  generate
    if (SHARED_STATE) begin : g_shared
      // DESAIN UTAMA: state Ascon = register file baseline
      //   x0 = {reg1, reg0}  x1 = {reg3, reg2}  x2 = {reg5, reg4}
      //   x3 = {reg7, reg6}  x4 = {reg9, reg8}   -> nonce/tag di alamat 24..39
      assign x0 = {register_file[1], register_file[0]};
      assign x1 = {register_file[3], register_file[2]};
      assign x2 = {register_file[5], register_file[4]};
      assign x3 = {register_file[7], register_file[6]};
      assign x4 = {register_file[9], register_file[8]};
      assign win_byte = rf_byte;
    end else begin : g_separate
      // KHUSUS PEMBANDING AREA: state Ascon di register 320 bit sendiri.
      // Susunannya sengaja sama dengan register file baseline (10 x 32 bit, jalur baca
      // word + byte, tulis per byte) supaya perbandingan area adil.
      reg [31:0] sreg [0:9];
      assign x0 = {sreg[1], sreg[0]};
      assign x1 = {sreg[3], sreg[2]};
      assign x2 = {sreg[5], sreg[4]};
      assign x3 = {sreg[7], sreg[6]};
      assign x4 = {sreg[9], sreg[8]};

      wire [31:0] s_word = sreg[io_addr[5:2]];
      reg  [7:0]  s_byte;
      always @(*) begin
        case (io_addr[1:0])
          2'd0:    s_byte = s_word[7:0];
          2'd1:    s_byte = s_word[15:8];
          2'd2:    s_byte = s_word[23:16];
          default: s_byte = s_word[31:24];
        endcase
      end
      assign win_byte = s_byte;

      integer j;
      always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
          for (j = 0; j < 10; j = j + 1) sreg[j] <= 32'h0;
        end else if (zeroize) begin
          for (j = 0; j < 10; j = j + 1) sreg[j] <= 32'h0;
        end else if (busy) begin
          sreg[0] <= x0_n[31:0];
          sreg[1] <= x0_n[63:32];
          sreg[2] <= x1_n[31:0];
          sreg[3] <= x1_n[63:32];
          sreg[4] <= x2_n[31:0];
          sreg[5] <= x2_n[63:32];
          sreg[6] <= x3_n[31:0];
          sreg[7] <= x3_n[63:32];
          sreg[8] <= x4_n[31:0];
          sreg[9] <= x4_n[63:32];
        end else if (win_wr) begin
          case (io_addr[1:0])
            2'd0: sreg[io_addr[5:2]][7:0]   <= uio_in;
            2'd1: sreg[io_addr[5:2]][15:8]  <= uio_in;
            2'd2: sreg[io_addr[5:2]][23:16] <= uio_in;
            2'd3: sreg[io_addr[5:2]][31:24] <= uio_in;
          endcase
        end
      end
    end
  endgenerate

  // ---------------------------------------------------------------------------
  // 5. mac_fsm — nilai state untuk tiap langkah (Ascon-AEAD128, AD & plaintext kosong)
  //    Urutan ini sama dengan SegelModel._run_mac() di work/ref/segel_model.py.
  // ---------------------------------------------------------------------------
  always @(*) begin
    x0_n = x0; x1_n = x1; x2_n = x2; x3_n = x3; x4_n = x4;
    case (fsm)
      S_LOAD: begin              // x3||x4 = nonce yang sudah ditulis host
        x0_n = ASCON_IV;
        x1_n = k0;
        x2_n = k1;
      end
      S_INIT, S_FIN: begin       // satu ronde Ascon-p per siklus
        x0_n = r0; x1_n = r1; x2_n = r2; x3_n = r3; x4_n = r4;
      end
      S_MID: begin               // akhir inisialisasi + pemisah domain + padding + awal finalisasi
        x0_n = x0 ^ 64'd1;                        // padding plaintext kosong
        x2_n = x2 ^ k0;                           // S ^ (0^128 || K || 0^64)
        x3_n = x3 ^ k0 ^ k1;                      // ^ (0^192 || K) dan ^ (0^128 || K || 0^64)
        x4_n = x4 ^ k1 ^ {1'b1, 63'd0};           // ^ K, ^ pemisah domain (AD kosong)
      end
      S_TAG: begin               // tag = x3||x4 ^ K; sisa state yang memuat kunci dinolkan (S3)
        x0_n = 64'd0;
        x1_n = 64'd0;
        x2_n = 64'd0;
        x3_n = x3 ^ k0;
        x4_n = x4 ^ k1;
      end
      default: ;
    endcase
  end

  // S2: kebijakan baca
  reg [7:0] rd_data;
  always @(*) begin
    rd_data = 8'h00;
    if (is_reg) begin
      if (!mode_ascon)          rd_data = rf_byte;   // mode SHA: semua register terbaca (baseline)
      else if (is_win && !busy) rd_data = win_byte;  // mode Ascon: hanya nonce/tag, tidak saat BUSY
    end else if (is_ctrl) begin
      rd_data = status;
    end else if (io_addr == ADDR_VERSION) begin
      rd_data = VERSION;
    end
    // kunci 40..55, cadangan 58..62, dan 63 selalu terbaca 0 (S1)
  end

  // ---------------------------------------------------------------------------
  // 6. Always block utama
  // ---------------------------------------------------------------------------
  integer i;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      for (i = 0; i < 10; i = i + 1) register_file[i] <= 32'h0;
      key        <= 128'h0;  // S4: reset menghapus kunci
      io_clk_q   <= 1'b1;    // io_clk yang sudah tinggi saat reset dilepas tidak dihitung sebagai tepi
      io_out     <= 8'h0;
      io_ready   <= 1'b0;
      mode_ascon <= 1'b0;
      busy       <= 1'b0;
      done       <= 1'b0;
      key_valid  <= 1'b0;
      err        <= 1'b0;
      fsm        <= S_IDLE;
      rnd        <= 4'd0;
    end else begin
      io_ready <= 1'b1;
      io_clk_q <= io_clk;

      // ---- tulis lewat bus ----
      if (bus_wr) begin
        if (busy) begin
          err <= 1'b1;  // S7: ditolak, tidak ada yang berubah

        end else if (is_reg) begin
          // Mode SHA: baseline apa adanya. Mode Ascon: hanya jendela nonce 24..39;
          // alamat 0..23 diabaikan supaya x0..x2 tetap nol sampai START.
          if (!mode_ascon || (is_win && SHARED_STATE)) begin
            case (io_addr[1:0])
              2'd0: register_file[io_addr[5:2]][7:0]   <= uio_in;
              2'd1: register_file[io_addr[5:2]][15:8]  <= uio_in;
              2'd2: register_file[io_addr[5:2]][23:16] <= uio_in;
              2'd3: register_file[io_addr[5:2]][31:24] <= uio_in;
            endcase
          end
          if (mode_ascon && is_win) done <= 1'b0;  // nonce baru: tag lama tidak berlaku

        end else if (is_key) begin
          key[{key_off[3:0], 3'b000} +: 8] <= uio_in;
          if (io_addr == ADDR_KEY_LO) key_valid <= 1'b0;
          if (io_addr == ADDR_KEY_HI) key_valid <= 1'b1;

        end else if (is_ctrl) begin
          err        <= 1'b0;  // setiap tulisan CTRL menghapus ERR dulu
          mode_ascon <= new_mode;
          if (uio_in[CTRL_KEYCLR]) begin
            key       <= 128'h0;  // S4
            key_valid <= 1'b0;
          end
          if (zeroize) begin
            for (i = 0; i < 10; i = i + 1) register_file[i] <= 32'h0;  // S3
            done <= 1'b0;
          end
          if (uio_in[CTRL_START]) begin
            if (new_mode && key_valid && !uio_in[CTRL_KEYCLR]) begin
              busy <= 1'b1;
              done <= 1'b0;
              fsm  <= S_LOAD;
              rnd  <= 4'd0;
            end else begin
              err <= 1'b1;  // S7: START tanpa kunci atau di mode SHA
            end
          end

        end else if (is_sha) begin
          if (mode_ascon) begin
            err <= 1'b1;  // S7: ronde SHA ditolak di mode Ascon
          end else begin
            // baseline: satu ronde kompresi SHA-256
            `A_reg <= sha_a;
            `B_reg <= `A_reg;
            `C_reg <= `B_reg;
            `D_reg <= `C_reg;
            `E_reg <= sha_e;
            `F_reg <= `E_reg;
            `G_reg <= `F_reg;
            `H_reg <= `G_reg;
          end
        end
        // alamat 57..62: tulisan diabaikan
      end

      // ---- baca lewat bus ----
      if (bus_rd) io_out <= rd_data;

      // ---- mac_fsm: 27 siklus, tidak bergantung pada nilai kunci/nonce (S5) ----
      if (busy) begin
        case (fsm)
          S_LOAD: fsm <= S_INIT;
          S_INIT: begin
            rnd <= rnd + 4'd1;
            if (rnd == 4'd11) begin
              rnd <= 4'd0;
              fsm <= S_MID;
            end
          end
          S_MID: fsm <= S_FIN;
          S_FIN: begin
            rnd <= rnd + 4'd1;
            if (rnd == 4'd11) begin
              rnd <= 4'd0;
              fsm <= S_TAG;
            end
          end
          S_TAG: begin
            fsm  <= S_IDLE;
            busy <= 1'b0;
            done <= 1'b1;
          end
          default: begin
            fsm  <= S_IDLE;
            busy <= 1'b0;
          end
        endcase

        if (SHARED_STATE) begin
          register_file[0] <= x0_n[31:0];
          register_file[1] <= x0_n[63:32];
          register_file[2] <= x1_n[31:0];
          register_file[3] <= x1_n[63:32];
          register_file[4] <= x2_n[31:0];
          register_file[5] <= x2_n[63:32];
          register_file[6] <= x3_n[31:0];
          register_file[7] <= x3_n[63:32];
          register_file[8] <= x4_n[31:0];
          register_file[9] <= x4_n[63:32];
        end
      end
    end
  end

endmodule
