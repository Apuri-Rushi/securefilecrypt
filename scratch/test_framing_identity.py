import io
import struct

def test_framing_concatenation_identity():
    # Simulate framing
    test_data = [
        b"A" * 64 * 1024,
        b"B" * 32 * 1024,
        b"C" * 100,
        b"",
    ]
    
    # Method A: Concatenated
    buf_a = io.BytesIO()
    for idx, chunk in enumerate(test_data):
        is_last = (idx == len(test_data) - 1)
        frame_header = struct.pack(">IB", len(chunk), 1 if is_last else 0)
        buf_a.write(frame_header + chunk)
        
    # Method B: Sequential
    buf_b = io.BytesIO()
    for idx, chunk in enumerate(test_data):
        is_last = (idx == len(test_data) - 1)
        frame_header = struct.pack(">IB", len(chunk), 1 if is_last else 0)
        buf_b.write(frame_header)
        buf_b.write(chunk)
        
    assert buf_a.getvalue() == buf_b.getvalue()
    print("Framing output identity verified: byte-for-byte identical (len:", len(buf_a.getvalue()), ")")

if __name__ == "__main__":
    test_framing_concatenation_identity()
