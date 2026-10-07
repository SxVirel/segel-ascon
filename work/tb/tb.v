`default_nettype none
`timescale 1ns / 1ps

/* Testbench pembungkus untuk cocotb (pola sama dengan tb.v baseline).
   Parameter SHARED_STATE diteruskan ke desain: 1 = desain utama, 0 = pembanding area.
*/
module tb ();

  parameter SHARED_STATE = 1;

  // Dump the signals to a VCD file. You can view it with gtkwave.
  initial begin
    $dumpfile("tb.vcd");
    $dumpvars(0, tb);
    #1;
  end

  // Wire up the inputs and outputs:
  reg clk;
  reg rst_n;
  reg ena;
  reg [7:0] ui_in;
  reg [7:0] uio_in;
  wire [7:0] uo_out;
  wire [7:0] uio_out;
  wire [7:0] uio_oe;

  tt_um_sxvirel_segel_ascon #(
      .SHARED_STATE(SHARED_STATE)
  ) user_project (

      // Include power ports for the Gate Level test:
`ifdef GL_TEST
      .VPWR(1'b1),
      .VGND(1'b0),
`endif

      .ui_in  (ui_in),    // Dedicated inputs
      .uo_out (uo_out),   // Dedicated outputs
      .uio_in (uio_in),   // IOs: Input path
      .uio_out(uio_out),  // IOs: Output path
      .uio_oe (uio_oe),   // IOs: Enable path (active high: 0=input, 1=output)
      .ena    (ena),      // enable - goes high when design is selected
      .clk    (clk),      // clock
      .rst_n  (rst_n)     // not reset
  );

`ifndef GL_TEST
  // Jendela pengamatan internal (white-box) untuk uji keamanan S3/S4.
  // Hanya ada di simulasi; chip tidak punya jalur ini.
  wire [127:0] dbg_key = user_project.key;
  wire [63:0]  dbg_x0  = user_project.x0;
  wire [63:0]  dbg_x1  = user_project.x1;
  wire [63:0]  dbg_x2  = user_project.x2;
  wire [63:0]  dbg_x3  = user_project.x3;
  wire [63:0]  dbg_x4  = user_project.x4;
`endif

endmodule
