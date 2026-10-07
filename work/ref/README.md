# work/ref — model referensi

| File | Isi | Sumber |
|---|---|---|
| `pyascon/ascon.py` | Implementasi referensi Ascon (Python) dari tim Ascon, sesuai NIST SP 800-232. Disalin apa adanya | https://github.com/meichlseder/pyascon, commit `ed24e54` (18 Nov 2025), lisensi CC0-1.0 |
| `kat/LWC_AEAD_KAT_128_128.txt` | Test vector resmi (KAT) Ascon-AEAD128, 1.089 entri | https://github.com/ascon/ascon-c, file `crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt`, commit `446347f` (28 Jan 2026), lisensi CC0-1.0 |
| `segel_model.py` | Model desain tingkat register (10 × 32 bit seperti baseline): cek pyascon vs KAT, urutan langkah FSM, bukti kebocoran kunci jika state boleh dibaca, dan hitungan siklus | Ditulis tim |

Cara menjalankan (Python 3.10+, tanpa paket tambahan):

```bash
python work/ref/segel_model.py
```
