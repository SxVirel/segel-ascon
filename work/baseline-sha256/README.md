# Salinan baseline TT07 #0718 "tiny sha256" untuk pengujian

Salinan dari https://github.com/xeniarose/tt07-sha256 (commit `655efb8`, lisensi Apache-2.0, lihat `LICENSE`).

## Perubahan terhadap aslinya

- `test/Makefile`: `MODULE = test,test_extra` (menjalankan test asli + test tambahan).
- `test/test_extra.py` (baru):
  - `test_nist_vectors_and_cycle_count` — menghitung SHA-256 untuk dua contoh resmi FIPS 180-2 (`"abc"` dan pesan 2 blok) dan mengukur jumlah siklus clock per blok.
  - `test_ioclk_held_two_cycles` — menahan sinyal perintah `io_clk` selama 2 siklus clock untuk melihat berapa ronde yang tereksekusi.
- `src/` dan `test/test.py`, `test/tb.v` tidak diubah.

## Cara menjalankan (tanpa install)

Setiap push yang mengubah folder ini otomatis menjalankan workflow `.github/workflows/test-baseline-sha256.yaml` di GitHub. Hasil: tab **Actions** di repo → run "test-baseline-sha256". File `tb.vcd` (gelombang sinyal), `results.xml`, dan `measurements.json` bisa diunduh di bagian *Artifacts* halaman run tersebut. Bisa juga dijalankan manual lewat tombol "Run workflow".
