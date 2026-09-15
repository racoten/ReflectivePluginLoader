import sys
import os
from textwrap import wrap

def file_to_cpp_hex_array(filename, var_name="embeddedBytes", bytes_per_line=16):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Failed to read file: {e}")
        return

    size = len(data)
    hex_lines = []
    for line in wrap(data.hex(), bytes_per_line * 2):  # 2 hex chars per byte
        hex_bytes = ", ".join(f"0x{line[i:i+2]}" for i in range(0, len(line), 2))
        hex_lines.append(f"    {hex_bytes},")

    cpp_code = f"""\
#include <cstdint>

constexpr std::size_t {var_name}_size = {size};

const uint8_t {var_name}[] = {{
{os.linesep.join(hex_lines)}
}};
"""
    print(cpp_code)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 file2hex.py <filename> [var_name]")
    else:
        file_to_cpp_hex_array(
            filename=sys.argv[1],
            var_name=sys.argv[2] if len(sys.argv) >= 3 else "embeddedBytes"
        )
