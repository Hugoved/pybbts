import argparse
import os
import math
import re
import sys
import time
try:
    from Crypto.Cipher import AES as CryptoAES
except Exception:
    CryptoAES = None
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:
    Cipher = None
    algorithms = None
    modes = None

TS_PACKET_SIZE = 188

def make_aes_encryptor(key):
    if CryptoAES is not None:
        cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
        return cipher.encrypt
    if Cipher is not None:
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        def cryptography_encrypt(block):
            return encryptor.update(block)
        return cryptography_encrypt
    raise RuntimeError("Missing AES backend. Install pycryptodome or cryptography.")

def hex_to_bytes(value):
    value = value.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        raise ValueError("AES key must be 32 hex characters")
    return bytes.fromhex(value)

def printable_text(data):
    return "".join(chr(x) for x in data if 32 <= x <= 126)

def packet_info(packet):
    if len(packet) != TS_PACKET_SIZE or packet[0] != 0x47:
        return -1, False, 0, 0, None
    pid = ((packet[1] & 0x1F) << 8) | packet[2]
    payload_unit_start = (packet[1] & 0x40) != 0
    adaptation_field_control = (packet[3] >> 4) & 0x03
    continuity_counter = packet[3] & 0x0F
    payload_offset = 4
    if adaptation_field_control in (2, 3):
        if payload_offset >= TS_PACKET_SIZE:
            return pid, payload_unit_start, adaptation_field_control, continuity_counter, None
        adaptation_length = packet[payload_offset]
        payload_offset += 1 + adaptation_length
        if payload_offset > TS_PACKET_SIZE:
            return pid, payload_unit_start, adaptation_field_control, continuity_counter, None
    if adaptation_field_control not in (1, 3):
        return pid, payload_unit_start, adaptation_field_control, continuity_counter, None
    return pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset

def parse_pat(packet):
    pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
    if pid != 0 or payload_offset is None:
        return {}
    payload = packet[payload_offset:]
    if payload_unit_start:
        if not payload:
            return {}
        pointer = payload[0]
        payload = payload[1 + pointer:]
    if len(payload) < 8 or payload[0] != 0x00:
        return {}
    section_length = ((payload[1] & 0x0F) << 8) | payload[2]
    section = payload[:3 + section_length]
    programs = {}
    i = 8
    end = len(section) - 4
    while i + 4 <= end:
        program_number = (section[i] << 8) | section[i + 1]
        program_map_pid = ((section[i + 2] & 0x1F) << 8) | section[i + 3]
        if program_number:
            programs[program_number] = program_map_pid
        i += 4
    return programs

def descriptor_text(descriptors):
    values = []
    i = 0
    while i + 2 <= len(descriptors):
        tag = descriptors[i]
        size = descriptors[i + 1]
        value = descriptors[i + 2:i + 2 + size]
        if i + 2 + size > len(descriptors):
            break
        if tag == 0x0A and len(value) >= 3:
            lang = value[:3].decode("latin-1", "ignore")
            values.append("language=" + lang)
        elif tag == 0x05 and value:
            values.append("registration=" + value.decode("latin-1", "ignore"))
        else:
            values.append("descriptor=0x%02x" % tag)
        i += 2 + size
    return values

def stream_type_name(stream_type):
    names = {
        0x01: ("vide", "mp1v", "MPEG-1_video"),
        0x02: ("vide", "mp2v", "MPEG-2_video"),
        0x0F: ("soun", "mp4a", "AAC_ADTS_audio"),
        0x1B: ("vide", "avc1", "H.264_AVC_video"),
        0x24: ("vide", "hvc1", "H.265_HEVC_video"),
        0x06: ("data", "data", "private_data"),
        0x81: ("soun", "ac-3", "AC3_audio"),
        0x87: ("soun", "ec-3", "EAC3_audio")
    }
    return names.get(stream_type, ("data", "data", "unknown"))

def parse_pmt(packet, program_number):
    pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
    if payload_offset is None:
        return []
    payload = packet[payload_offset:]
    if payload_unit_start:
        if not payload:
            return []
        pointer = payload[0]
        payload = payload[1 + pointer:]
    if len(payload) < 12 or payload[0] != 0x02:
        return []
    section_length = ((payload[1] & 0x0F) << 8) | payload[2]
    section = payload[:3 + section_length]
    if len(section) < 16:
        return []
    pcr_pid = ((section[8] & 0x1F) << 8) | section[9]
    program_info_length = ((section[10] & 0x0F) << 8) | section[11]
    i = 12 + program_info_length
    end = len(section) - 4
    tracks = []
    track_index = 1
    while i + 5 <= end:
        stream_type = section[i]
        elementary_pid = ((section[i + 1] & 0x1F) << 8) | section[i + 2]
        es_info_length = ((section[i + 3] & 0x0F) << 8) | section[i + 4]
        descriptors = section[i + 5:i + 5 + es_info_length]
        descriptor_values = descriptor_text(descriptors)
        handler, entry, codec = stream_type_name(stream_type)
        if stream_type == 0x06 and any(value == "registration=DOVI" for value in descriptor_values):
            handler = "vide"
            entry = "dovi"
            codec = "Dolby_Vision_video"
        tracks.append({
            "track": track_index,
            "pid": elementary_pid,
            "program": program_number,
            "stream_type": stream_type,
            "handler": handler,
            "entry": entry,
            "codec": codec,
            "pcr": elementary_pid == pcr_pid,
            "descriptors": descriptor_values,
            "encrypted": "no",
            "scheme": "none"
        })
        track_index += 1
        i += 5 + es_info_length
    return tracks

def detect_tracks(data):
    programs = {}
    tracks = []
    pmt_pids = set()
    for offset in range(0, len(data) - TS_PACKET_SIZE + 1, TS_PACKET_SIZE):
        packet = data[offset:offset + TS_PACKET_SIZE]
        pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
        if pid == 0:
            found = parse_pat(packet)
            programs.update(found)
            pmt_pids.update(found.values())
        elif pid in pmt_pids:
            program_number = 0
            for number, pmt_pid in programs.items():
                if pmt_pid == pid:
                    program_number = number
                    break
            found_tracks = parse_pmt(packet, program_number)
            if found_tracks:
                tracks = found_tracks
                break
    return tracks

def short_descriptor_text(track):
    values = []
    for value in track["descriptors"]:
        if value.startswith("registration="):
            values.append(value.split("=", 1)[1])
        elif value.startswith("language="):
            values.append(value)
    return ",".join(values)

def format_track(track, bbts_video_encrypted):
    encrypted = "yes" if bbts_video_encrypted and track_is_decryptable_video(track) else "no"
    scheme = "bbts" if encrypted == "yes" else "none"
    parts = [
        "  track=%d" % track["track"],
        "handler=%s" % track["handler"],
        "entry=%s" % track["entry"],
        "encrypted=%s" % encrypted,
        "scheme=%s" % scheme,
        "pid=%d" % track["pid"],
        "codec=%s" % track["codec"]
    ]
    descriptors = short_descriptor_text(track)
    if descriptors:
        parts.append("descriptors=" + descriptors)
    return " ".join(parts)

def find_block_key(data):
    for offset in range(0, len(data) - TS_PACKET_SIZE + 1, TS_PACKET_SIZE):
        packet = data[offset:offset + TS_PACKET_SIZE]
        pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
        if pid == 17:
            match = re.search(r"\|v([0-9a-fA-F]{32})\|", printable_text(packet[4:]))
            if match:
                return bytes.fromhex(match.group(1))
    return b""

def find_start_codes(data):
    starts = []
    position = 0
    length = len(data)
    while True:
        marker = data.find(b"\x00\x00\x01", position)
        if marker < 0:
            break
        start = marker - 1 if marker > 0 and data[marker - 1] == 0 else marker
        size = 4 if start != marker else 3
        if not starts or starts[-1][0] != start:
            starts.append((start, size))
        position = marker + 3
        if position >= length:
            break
    return starts

def mpeg_crc32(data):
    crc = 0xffffffff
    for value in data:
        crc ^= value << 24
        for unused in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04c11db7) & 0xffffffff
            else:
                crc = (crc << 1) & 0xffffffff
    return crc & 0xffffffff

def hevc_nal_type_from_annexb_unit(unit):
    if unit.startswith(b"\x00\x00\x00\x01"):
        offset = 4
    elif unit.startswith(b"\x00\x00\x01"):
        offset = 3
    else:
        return -1
    if len(unit) < offset + 2:
        return -1
    return (unit[offset] >> 1) & 0x3f

def dolby_rpu_rbsp_positions_from_ebsp(ebsp):
    positions = []
    zeros = 0
    for index, value in enumerate(ebsp):
        if zeros == 2 and value == 0x03:
            zeros = 0
            continue
        positions.append(index)
        if value == 0x00:
            zeros += 1
            if zeros > 2:
                zeros = 2
        else:
            zeros = 0
    return positions

def find_valid_dolby_rpu_rbsp_end(rbsp):
    if len(rbsp) < 8 or rbsp[0] != 0x19:
        return len(rbsp)
    for end_index in range(len(rbsp) - 1, 5, -1):
        if rbsp[end_index] != 0x80:
            continue
        crc_start = end_index - 4
        if crc_start <= 1:
            continue
        received_crc = int.from_bytes(rbsp[crc_start:end_index], "big")
        expected_crc = mpeg_crc32(rbsp[1:crc_start])
        if received_crc == expected_crc:
            return end_index + 1
    return len(rbsp)

def trim_dolby_rpu_to_valid_crc_end(unit):
    if hevc_nal_type_from_annexb_unit(unit) != 62:
        return unit
    if unit.startswith(b"\x00\x00\x00\x01"):
        start_code_length = 4
    elif unit.startswith(b"\x00\x00\x01"):
        start_code_length = 3
    else:
        return unit
    payload_start = start_code_length + 2
    if len(unit) < payload_start + 12:
        return unit
    ebsp = unit[payload_start:]
    rbsp_positions = dolby_rpu_rbsp_positions_from_ebsp(ebsp)
    if len(rbsp_positions) < 8:
        return unit
    rbsp = bytes(ebsp[position] for position in rbsp_positions)
    valid_rbsp_end = find_valid_dolby_rpu_rbsp_end(rbsp)
    if valid_rbsp_end >= len(rbsp):
        return unit
    last_ebsp_index = rbsp_positions[valid_rbsp_end - 1]
    return unit[:payload_start + last_ebsp_index + 1]

def decrypt_nal_vb(input_stream, block_key, encrypt_block, trailer_size):
    loc11 = bytearray(input_stream)
    loc9 = bytearray(len(loc11))
    loc22 = 0
    loc23 = 0
    while loc22 < len(loc11):
        if loc22 + 3 < len(loc11) and loc11[loc22] == 0 and loc11[loc22 + 1] == 0 and loc11[loc22 + 2] == 3 and loc11[loc22 + 3] in (0, 1, 2, 3):
            loc9[loc23] = loc11[loc22]
            loc23 += 1
            loc9[loc23] = loc11[loc22 + 1]
            loc23 += 1
            loc9[loc23] = loc11[loc22 + 3]
            loc23 += 1
            loc22 += 4
        else:
            loc9[loc23] = loc11[loc22]
            loc22 += 1
            loc23 += 1
    payload_size = loc23 - 5 - trailer_size
    if payload_size <= 0:
        return bytes(loc11)
    loc12 = bytearray(loc9[5:5 + payload_size])
    block_count = math.ceil(len(loc12) / 16)
    loc14 = 0
    for block_index in range(1, block_count + 1):
        loc17 = block_key[:12] + block_index.to_bytes(4, "big")
        if block_index % 10 == 1 or block_index == block_count:
            loc17 = encrypt_block(loc17)
        for value in loc17:
            if loc14 == len(loc12):
                break
            loc12[loc14] ^= value
            loc14 += 1
    loc11[5:5 + len(loc12)] = loc12
    loc11[5 + len(loc12):5 + len(loc12) + trailer_size] = loc9[5 + len(loc12):5 + len(loc12) + trailer_size]
    loc10 = len(loc11) - 5 - len(loc12) - trailer_size
    if loc10 > 0:
        for unused in range(loc10):
            loc11[len(loc11) - loc10] = 0
    return bytes(loc11)


def increment_counter(counter):
    carry = 1
    for index in range(15, -1, -1):
        value = counter[index] + carry
        counter[index] = value & 0xff
        carry = value >> 8
        if carry == 0:
            break

def decrypt_es_sparse_stripped_with_padding(es, key, iv_start):
    stripped = bytearray()
    index = 0
    while index < len(es):
        if index + 2 < len(es) and es[index] == 0x00 and es[index + 1] == 0x00 and es[index + 2] == 0x03:
            stripped.extend(b"\x00\x00")
            index += 3
        else:
            stripped.append(es[index])
            index += 1
    counter = bytearray(16)
    counter[:min(16, len(iv_start))] = iv_start[:16]
    output = bytearray(stripped)
    remaining = len(output)
    position = 0
    block_index = 0
    encrypt_block = make_aes_encryptor(key)
    while remaining > 0:
        increment_counter(counter)
        temporary = bytes(counter)
        if remaining <= 16 or block_index % 10 == 0:
            temporary = encrypt_block(temporary)
        decrypt_length = min(16, remaining)
        for byte_index in range(decrypt_length):
            output[position + byte_index] ^= temporary[byte_index]
        remaining -= decrypt_length
        position += 16
        block_index += 1
    if len(output) != len(es):
        difference = len(es) - len(output)
        if difference > 0:
            output.extend(es[len(es) - difference:])
        elif difference < 0:
            output = output[:len(es)]
    return bytes(output)

def trim_dolby_rpu_nal_payload(payload):
    if len(payload) < 8:
        return payload
    ebsp = payload[2:]
    positions = dolby_rpu_rbsp_positions_from_ebsp(ebsp)
    rbsp = bytes(ebsp[position] for position in positions)
    valid_rbsp_end = find_valid_dolby_rpu_rbsp_end(rbsp)
    if valid_rbsp_end <= 0 or valid_rbsp_end > len(positions):
        return payload
    return payload[:2 + positions[valid_rbsp_end - 1] + 1]

def dolby_rpu_payload_is_crc_valid(payload):
    if len(payload) < 10:
        return False
    ebsp = payload[2:]
    positions = dolby_rpu_rbsp_positions_from_ebsp(ebsp)
    if len(positions) < 8:
        return False
    rbsp = bytes(ebsp[position] for position in positions)
    if len(rbsp) < 8 or rbsp[0] != 0x19:
        return False
    for end_index in range(len(rbsp) - 1, 5, -1):
        if rbsp[end_index] != 0x80:
            continue
        crc_start = end_index - 4
        if crc_start <= 1:
            continue
        received_crc = int.from_bytes(rbsp[crc_start:end_index], "big")
        expected_crc = mpeg_crc32(rbsp[1:crc_start])
        if received_crc == expected_crc:
            return True
    return False

def decrypt_dolby_rpu_unit(unit, key, block_key):
    if hevc_nal_type_from_annexb_unit(unit) != 62:
        return None
    if unit.startswith(b"\x00\x00\x00\x01"):
        start_code = b"\x00\x00\x00\x01"
        start_code_length = 4
    elif unit.startswith(b"\x00\x00\x01"):
        start_code = b"\x00\x00\x00\x01"
        start_code_length = 3
    else:
        return None
    if len(unit) < start_code_length + 2:
        return None
    nal_prefix = unit[start_code_length:start_code_length + 2]
    encrypted_source_full = unit[start_code_length + 2:]
    iv_snapshot = bytearray(16)
    iv_snapshot[:min(12, len(block_key))] = block_key[:12]
    best_payload = None
    for tail_drop in (4, 0, 2, 1, 3, 5, 6, 7, 8, 12, 16):
        encrypted_end = max(0, len(encrypted_source_full) - tail_drop)
        encrypted_source = encrypted_source_full[:encrypted_end]
        candidate = bytearray(nal_prefix)
        if encrypted_source:
            candidate.extend(decrypt_es_sparse_stripped_with_padding(encrypted_source, key, bytes(iv_snapshot)))
        candidate = bytearray(trim_dolby_rpu_nal_payload(bytes(candidate)))
        if best_payload is None:
            best_payload = bytes(candidate)
        if dolby_rpu_payload_is_crc_valid(bytes(candidate)):
            return start_code + bytes(candidate)
    if best_payload is None:
        return unit
    return start_code + best_payload

def decrypt_es(input_stream, block_key, encrypt_block, decryption_key):
    starts = find_start_codes(input_stream)
    if not starts:
        return input_stream
    output = bytearray()
    if starts[0][0] > 0:
        output.extend(input_stream[:starts[0][0]])
    for index, item in enumerate(starts):
        start, start_size = item
        end = starts[index + 1][0] if index + 1 < len(starts) else len(input_stream)
        nal = input_stream[start:end]
        rpu_decrypted = decrypt_dolby_rpu_unit(nal, decryption_key, block_key)
        if rpu_decrypted is not None:
            output.extend(rpu_decrypted)
            continue
        trailer_size = 4 if index + 1 == len(starts) else 2
        decrypted = decrypt_nal_vb(nal, block_key, encrypt_block, trailer_size)
        if start_size == 3 and len(decrypted) >= 4:
            output.extend(b"\x00" + decrypted[:-4])
        else:
            output.extend(decrypted)
    return bytes(output)


def make_payload_packet_from_original(packet, payload):
    pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
    if payload_offset is None or payload_offset > TS_PACKET_SIZE:
        payload_offset = 4
        adaptation_field_control = 1
    original_header = bytearray(packet[:payload_offset])
    payload_capacity = TS_PACKET_SIZE - len(original_header)
    if payload_capacity < 0:
        payload_capacity = 0
    if len(payload) > payload_capacity:
        payload = payload[:payload_capacity]
    stuffing_needed = payload_capacity - len(payload)
    if stuffing_needed <= 0:
        output_header = bytearray(original_header)
        if len(output_header) >= 4:
            output_header[3] = (output_header[3] & 0xcf) | (adaptation_field_control << 4)
        return bytes(output_header + payload).ljust(TS_PACKET_SIZE, b"\xff")[:TS_PACKET_SIZE]
    if adaptation_field_control == 3 and len(original_header) >= 5:
        old_length = original_header[4]
        new_length = old_length + stuffing_needed
        if new_length <= 183:
            output_header = bytearray(original_header)
            output_header[3] = (output_header[3] & 0xcf) | 0x30
            output_header[4] = new_length
            output_header.extend(b"\xff" * stuffing_needed)
            return bytes(output_header + payload).ljust(TS_PACKET_SIZE, b"\xff")[:TS_PACKET_SIZE]
    base_header = bytearray(packet[:4])
    base_header[3] = (base_header[3] & 0xcf) | 0x30
    adaptation_length = stuffing_needed - 1
    output = bytearray(base_header)
    output.append(adaptation_length)
    if adaptation_length > 0:
        output.append(0x00)
        if adaptation_length > 1:
            output.extend(b"\xff" * (adaptation_length - 1))
    output.extend(payload)
    return bytes(output).ljust(TS_PACKET_SIZE, b"\xff")[:TS_PACKET_SIZE]

def make_adaptation_only_packet_from_original(packet):
    header = bytearray(packet[:4])
    header[3] = (header[3] & 0xcf) | 0x20
    pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
    content = b""
    if adaptation_field_control == 3 and len(packet) >= 5:
        old_length = packet[4]
        old_end = min(5 + old_length, TS_PACKET_SIZE)
        content = packet[5:old_end]
    if len(content) > 183:
        content = content[:183]
    return bytes(header) + bytes([183]) + content + b"\xff" * (183 - len(content))

def update_pes_packet_length_if_needed(prefix, payload_length):
    if len(prefix) < 6 or prefix[:3] != b"\x00\x00\x01":
        return prefix
    current_length = (prefix[4] << 8) | prefix[5]
    if current_length == 0:
        return prefix
    new_length = len(prefix) + payload_length - 6
    if new_length < 0 or new_length > 0xffff:
        return prefix
    output = bytearray(prefix)
    output[4] = (new_length >> 8) & 0xff
    output[5] = new_length & 0xff
    return bytes(output)

def patch_group_in_output(output_handle, group_entries, block_key, encrypt_block, decryption_key):
    if not group_entries or block_key is None or len(block_key) != 16:
        return False
    payload = bytearray()
    packet_parts = []
    for entry in group_entries:
        packet = entry["packet"]
        pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
        if payload_offset is None:
            continue
        pes_header = b""
        payload_start = payload_offset
        if payload_unit_start:
            packet_payload = packet[payload_offset:]
            if len(packet_payload) >= 9 and packet_payload[:3] == b"\x00\x00\x01":
                pes_header_size = 9 + packet_payload[8]
                if pes_header_size <= len(packet_payload):
                    pes_header = packet_payload[:pes_header_size]
                    payload_start = payload_offset + pes_header_size
        packet_parts.append({"offset": entry["offset"], "packet": packet, "payload_unit_start": payload_unit_start, "pes_header": pes_header})
        payload.extend(packet[payload_start:])
    if not packet_parts:
        return False
    decrypted = decrypt_es(bytes(payload), block_key, encrypt_block, decryption_key)
    position = 0
    ended = False
    return_position = output_handle.tell()
    for part in packet_parts:
        packet = part["packet"]
        if ended:
            rebuilt_packet = make_adaptation_only_packet_from_original(packet)
            output_handle.seek(part["offset"])
            output_handle.write(rebuilt_packet)
            continue
        prefix = part["pes_header"] if part["payload_unit_start"] else b""
        if prefix:
            prefix = update_pes_packet_length_if_needed(prefix, len(decrypted))
        pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
        if payload_offset is None or payload_offset > TS_PACKET_SIZE:
            payload_offset = 4
        capacity = TS_PACKET_SIZE - payload_offset - len(prefix)
        if capacity < 0:
            capacity = 0
        remaining = len(decrypted) - position
        if remaining <= 0:
            if prefix:
                rebuilt_packet = make_payload_packet_from_original(packet, prefix)
            else:
                rebuilt_packet = make_adaptation_only_packet_from_original(packet)
            output_handle.seek(part["offset"])
            output_handle.write(rebuilt_packet)
            ended = True
            continue
        take = min(capacity, remaining)
        chunk = decrypted[position:position + take]
        position += take
        rebuilt_packet = make_payload_packet_from_original(packet, prefix + chunk)
        output_handle.seek(part["offset"])
        output_handle.write(rebuilt_packet)
        if position >= len(decrypted):
            ended = True
    output_handle.seek(return_position)
    return True

PROGRESS_LAST_LENGTH = 0
PROGRESS_LINE_ACTIVE = False

def format_hms(seconds):
    seconds = max(0, int(seconds))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    value_seconds = seconds % 60
    return "%02d:%02d:%02d" % (hours, minutes, value_seconds)

def print_progress(done, total, start_time, force=False):
    global PROGRESS_LAST_LENGTH
    global PROGRESS_LINE_ACTIVE
    percent = done / total if total else 1
    if percent > 1:
        percent = 1
    if percent < 0:
        percent = 0
    width = 40
    filled = int(width * percent)
    elapsed = max(0.001, time.monotonic() - start_time)
    if percent > 0:
        remaining = max(0, int((elapsed / percent) - elapsed))
    else:
        remaining = 0
    bar = "[" + "■" * filled + " " * (width - filled) + "]"
    line = "%s %6.2f%% (elapsed: %s, remaining: %s)" % (bar, percent * 100, format_hms(elapsed), format_hms(remaining))
    padding = " " * max(0, PROGRESS_LAST_LENGTH - len(line))
    sys.stdout.write("\r" + line + padding)
    sys.stdout.flush()
    PROGRESS_LAST_LENGTH = len(line)
    PROGRESS_LINE_ACTIVE = True

def clear_progress_line():
    global PROGRESS_LAST_LENGTH
    global PROGRESS_LINE_ACTIVE
    if PROGRESS_LINE_ACTIVE:
        sys.stdout.write("\r" + " " * PROGRESS_LAST_LENGTH + "\r")
        sys.stdout.flush()
        PROGRESS_LINE_ACTIVE = False
        PROGRESS_LAST_LENGTH = 0

def track_is_decryptable_video(track):
    if track["handler"] == "vide":
        return True
    if any(value == "registration=DOVI" for value in track["descriptors"]):
        return True
    return False

def extract_packet_block_key(packet):
    match = re.search(r"\|v([0-9a-fA-F]{32})\|", printable_text(packet[4:]))
    if match:
        return bytes.fromhex(match.group(1))
    return None

def print_detected_tracks_once(tracks, bbts_video_encrypted):
    clear_progress_line()
    print("Detected tracks:")
    for track in tracks:
        print(format_track(track, bbts_video_encrypted))
    sys.stdout.flush()

def decrypt_bbts_streaming(input_path, output_path, key, show_tracks):
    decryption_key = hex_to_bytes(key)
    encrypt_block = make_aes_encryptor(decryption_key)
    total_size = os.path.getsize(input_path)
    if total_size < TS_PACKET_SIZE:
        raise RuntimeError("Input file is too small to be a TS/BBTS file")
    programs = {}
    pmt_pids = set()
    tracks = []
    target_pids = set()
    fallback_video_pid = -1
    active_block_key = None
    printed_tracks = False
    current_groups = {}
    current_group_keys = {}
    start_time = time.monotonic()
    next_progress_time = 0.0
    next_progress_percent = -1
    def refresh_target_pids():
        nonlocal target_pids
        found = set(track["pid"] for track in tracks if track_is_decryptable_video(track))
        if found:
            target_pids = found
        elif fallback_video_pid >= 0:
            target_pids = {fallback_video_pid}
    def flush_group(output_handle, pid):
        group = current_groups.get(pid)
        group_key = current_group_keys.get(pid)
        if group:
            patch_group_in_output(output_handle, group, group_key, encrypt_block, decryption_key)
        current_groups[pid] = []
        current_group_keys[pid] = active_block_key
    with open(input_path, "rb") as source, open(output_path, "wb+") as output:
        done = 0
        while True:
            packet = source.read(TS_PACKET_SIZE)
            if not packet:
                break
            if len(packet) != TS_PACKET_SIZE:
                break
            output_offset = output.tell()
            output.write(packet)
            done += TS_PACKET_SIZE
            pid, payload_unit_start, adaptation_field_control, continuity_counter, payload_offset = packet_info(packet)
            if pid == 17:
                found_key = extract_packet_block_key(packet)
                if found_key is not None:
                    active_block_key = found_key
            if pid == 0:
                found_programs = parse_pat(packet)
                if found_programs:
                    programs.update(found_programs)
                    pmt_pids.update(found_programs.values())
            elif pid in pmt_pids:
                program_number = 0
                for number, pmt_pid in programs.items():
                    if pmt_pid == pid:
                        program_number = number
                        break
                found_tracks = parse_pmt(packet, program_number)
                if found_tracks:
                    tracks = found_tracks
                    refresh_target_pids()
            if not target_pids and payload_unit_start and active_block_key is not None and payload_offset is not None and 32 <= pid <= 256:
                fallback_video_pid = pid
                refresh_target_pids()
            if show_tracks and not printed_tracks and tracks and active_block_key is not None:
                print_detected_tracks_once(tracks, True)
                printed_tracks = True
            if pid in target_pids and payload_offset is not None:
                if payload_unit_start:
                    if pid in current_groups and current_groups[pid]:
                        flush_group(output, pid)
                    current_groups[pid] = []
                    current_group_keys[pid] = active_block_key
                if pid in current_groups:
                    current_groups[pid].append({"offset": output_offset, "packet": packet})
            now = time.monotonic()
            if total_size:
                percent_int = int(done * 100 / total_size)
                if percent_int != next_progress_percent or now >= next_progress_time:
                    print_progress(done, total_size, start_time)
                    next_progress_percent = percent_int
                    next_progress_time = now + 0.25
        for pid in list(current_groups.keys()):
            if current_groups[pid]:
                flush_group(output, pid)
        output.flush()
    if show_tracks and not printed_tracks and tracks:
        print_detected_tracks_once(tracks, active_block_key is not None)
    print_progress(total_size, total_size, start_time, True)
    print()

parser = argparse.ArgumentParser(prog="pybbts.py")
parser.add_argument("-i", "--input", required=True, help="Input .bbts file")
parser.add_argument("-k", "--key", required=True, help="128-bit AES key as 32 hex characters")
parser.add_argument("-o", "--output", required=True, help="Output .ts file")
parser.add_argument("--show-tracks", action="store_true", help="Print detected tracks before decryption")
args = parser.parse_args()

try:
    decrypt_bbts_streaming(args.input, args.output, args.key, args.show_tracks)
    print("Decrypted successfully")
except Exception as error:
    print("Error: %s" % error)
    sys.exit(1)
