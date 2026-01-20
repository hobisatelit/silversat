#!/usr/bin/env python3
# Copyleft 2026 hobisatelit
# https://github.com/hobisatelit/silversat
# License: GPL-3.0-or-later
# SSDV doc: https://ukhas.org.uk/doku.php?id=guides:ssdv

# This script connects to a Dire Wolf KISS TCP server (port 8001 by default)
# and extracts SSDV packets from IL2P payloads (211 bytes total).
#
# Payload structure from Dire Wolf KISS:
#   bytes 0–15:   IL2P header (ignored)
#   bytes 16–210: SSDV packet (195 bytes total)
#
# SSDV packet (195 bytes):
#   offset  0: sync        0x55
#   offset  1: sync        0x67
#   offset 2–5: callsign   4 bytes
#   offset  6: image ID    1 byte
#   offset 7–8: packet ID  2 bytes (big-endian)
#   offset 9–194: image data (186 bytes)

import socket
import argparse
import sys
import os
import subprocess
from collections import defaultdict

KISS_FEND = b'\xC0'
KISS_DATA_FRAME = 0x00

def ssdv_decoding(input_filename,output_filename):
  try:
    command = ["ssdv", "-d", "-l", "195", input_filename, output_filename]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  except FileNotFoundError:
    return None
  except subprocess.CalledProcessError as e:
    print(f"An error occurred while running {app_name}: {e}")
    return None

def kiss_unescape(data: bytes) -> bytes:
    """Remove KISS escaping from frame content"""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xDB and i + 1 < len(data):
            if data[i + 1] == 0xDC:
                out.append(0xC0)
            elif data[i + 1] == 0xDD:
                out.append(0xDB)
            else:
                out.append(0xDB)
                out.append(data[i + 1])
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)

def bytes_to_hex_preview(b: bytes, max_chars: int = 96) -> str:
    """Convert bytes to space-separated hex string, truncated if long"""
    hex_str = b.hex(' ')
    if len(hex_str) > max_chars:
        return hex_str[:max_chars] + '...'
    return hex_str

def parse_ssdv_packet(ssdv_bytes: bytes, verbose: bool = False) -> dict | None:
    """
    Validate and parse the 195-byte SSDV packet.
    Returns dict with callsign, image_id, packet_id, image_data if valid.
    """
    if len(ssdv_bytes) != 195:
        if verbose:
            print(f"  → Wrong SSDV length: {len(ssdv_bytes)} bytes (expected 195)")
        return None

    if ssdv_bytes[0] != 0x55 or ssdv_bytes[1] != 0x67:
        if verbose:
            print(f"  → Invalid sync bytes: {ssdv_bytes[0]:02X} {ssdv_bytes[1]:02X} (expected 55 67)")
        return None
    
    #callsign = bytes_to_hex_preview(ssdv_bytes[2:6], 1000)
    #callsign = callsign.replace(" ", "")
    
    callsign = int.from_bytes(ssdv_bytes[2:6])
    
	  # Decode the callsign
    code = callsign
    callsign = ''
    while code:
      callsign += '-0123456789---ABCDEFGHIJKLMNOPQRSTUVWXYZ'[code % 40]
      code //= 40

    if not callsign:
        callsign = "unknown"

    image_id  = ssdv_bytes[6]
    packet_id = (ssdv_bytes[7] << 8) | ssdv_bytes[8]

    if verbose:
        print(f"  → Parsed: Call={callsign}  Img={image_id:02X}  Pkt={packet_id:5d}")

    return {
        'callsign': callsign,
        'image_id': image_id,
        'packet_id': packet_id,
        'image_data': ssdv_bytes[0:]   # 186 bytes JPEG fragment
    }

def main(args):
    print(f"Connecting to Dire Wolf KISS TCP at {args.host}:{args.port} ...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        print("Connected.")
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    # output/ folder next to script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    print(f"Saving sorted SSDV image fragments (.bin) to: {output_dir}/")
    print("Expecting 211-byte KISS payloads → skip 16-byte IL2P header → take 195-byte SSDV")

    # (callsign, image_id) → {packet_id: image_data (186 bytes)}
    images = defaultdict(dict)
    total_valid = 0

    packet_buf = bytearray()
    in_frame = False

    while True:
        try:
            chunk = sock.recv(1024)
        except KeyboardInterrupt:
            print("\nInterrupted by user.")
            break
        except Exception as e:
            print(f"Socket error: {e}", file=sys.stderr)
            break

        if not chunk:
            print("Server closed connection.")
            break

        for byte in chunk:
            if byte == 0xC0:
                if in_frame:
                    # Frame complete
                    if len(packet_buf) >= 1:
                        frame_type = packet_buf[0]
                        payload = kiss_unescape(packet_buf[1:])

                        if frame_type == KISS_DATA_FRAME:
                            if len(payload) == 211:
                                ssdv_part = payload[16:]

                                if args.verbose:
                                    print(f"\nReceived SSDV candidate ({len(ssdv_part)} bytes):")
                                    print("" + bytes_to_hex_preview(ssdv_part, 1000))

                                parsed = parse_ssdv_packet(ssdv_part, verbose=args.verbose)
                                if parsed:
                                    key = (parsed['callsign'], parsed['image_id'])
                                    was_new = len(images[key]) == 0

                                    images[key][parsed['packet_id']] = parsed['image_data']

                                    fname = f"{parsed['callsign']}_{parsed['image_id']:02X}.bin"
                                    path = os.path.join(output_dir, fname)

                                    # Write in packet ID order
                                    with open(path, "wb") as f:
                                        for pid in sorted(images[key]):
                                            f.write(images[key][pid])

                                    total_valid += 1
                                    print(f"OK  Packet {parsed['packet_id']:5d} | {parsed['callsign']:<8} | "
                                          f"Img {parsed['image_id']:02X} | {len(images[key]):3d} frags | → {fname}")

                                    if was_new:
                                        print(f"    → New image: {parsed['callsign']} image {parsed['image_id']:02X}")

                                    ssdv_process = ssdv_decoding(os.path.join(output_dir, fname),os.path.join(output_dir, f"{fname}.jpg"))


                                else:
                                    if args.verbose:
                                        print("  → Rejected (invalid SSDV)")
                            else:
                                if args.verbose:
                                    print(f"  → Wrong payload length: {len(payload)} (expected 211)")

                    packet_buf = bytearray()
                    in_frame = False
                else:
                    in_frame = True
                    packet_buf = bytearray()
            elif in_frame:
                packet_buf.append(byte)

    sock.close()
    print(f"\nFinished. Processed {total_valid} valid SSDV packets.")

    if total_valid > 0:
        print("\nFiles created in output/:")
        for (call, img), frags in sorted(images.items()):
            print(f"  {call}_{img:02X}.bin  →  {len(frags)} fragments")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dire Wolf KISS TCP → SSDV (195 bytes after IL2P) → sorted .bin files"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dire Wolf host")
    parser.add_argument("--port", type=int, default=8001, help="Dire Wolf KISS TCP port")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print hex of each received SSDV candidate + parsing details")
    args = parser.parse_args()

    try:
        main(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
