# pybbts

**pybbts** is a Python-based tool designed for parsing and decrypting protected media streams in **BBTS/MPEG-TS** format. The project emphasizes accurate handling of transport stream structures, encryption metadata, and reliable **sample-level decryption** for HEVC video streams. 

---

## Features

* Support for **BBTS/MPEG-TS (188-byte packets)** streams
* Detection and parsing of **PAT/PMT tables** and track metadata
* Decryption of protected **HEVC (H.265) video streams**
* Accurate handling of **NAL units and start codes**
* Support for **block-based AES decryption schemes (bbts)**
* Automatic extraction of **per-stream block keys**
* Stream-oriented processing suitable for large files
* Optional **track detection output**

---

## Dolby Vision Handling

pybbts includes dedicated handling for **Dolby Vision RPU (NAL type 62)** data within HEVC streams.

* Detection and processing of **RPU NAL units**
* Removal of emulation prevention bytes (**EBSP → RBSP conversion**)
* Validation of **RPU integrity using CRC checks**
* Automatic trimming to the **last valid CRC-aligned payload**
* Reconstruction of valid RPU data after decryption

This ensures that Dolby Vision metadata remains **structurally correct and usable** after decryption, avoiding playback issues caused by corrupted or invalid RPU payloads.

---

## Requirements

* Python 3.9 or higher
* One of the following:

  * `pycryptodome`
  * `cryptography`

Installation:

```bash
pip install pycryptodome
```

or

```bash
pip install cryptography
```

---

## Usage

```bash
python pybbts.py -i input.bbts -o output.ts -k AES_KEY
```

---

## Script Example

```python
import sys
import pybbts

input_file = "input.bbts"
output_file = "output.ts"
key = "1242be72aadf80923351d25cba2ba62c"

show_tracks = True

try:
    pybbts.decrypt_bbts_streaming(
        input_path=input_file,
        output_path=output_file,
        key=key,
        show_tracks=show_tracks
    )

except KeyboardInterrupt:
    raise SystemExit(130)
except Exception as error:
    print(f"Decryption failed: {error}", file=sys.stderr)
    raise SystemExit(1)
```

---

## Notes

This project was developed to better understand the structure and encryption mechanisms of **BBTS transport streams**, including packet-level parsing, PID tracking, and NAL-based decryption.

The implementation focuses on correctness and reliability when reconstructing decrypted streams, preserving timing and structure during processing.

---

## Issues and Support

If you encounter any issues, please open an issue in the repository.
Support and maintenance will be provided as time permits.

---

## Acknowledgements

Thank you for your interest in this project.
