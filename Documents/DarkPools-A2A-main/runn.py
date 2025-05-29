import ctypes
import os
import sys
from typing import Tuple, Optional
import json

# Constants from Rust
FIELD_SIZE_BYTES = 8

# MPC Protocol Structures
class MPCEncryption:
    def __init__(self, public_key: bytes = None, private_key: bytes = None):
        self.public_key = public_key or bytes(32)  # Default 32-byte key
        self.private_key = private_key or bytes(32)
    
    def to_bytes(self) -> bytes:
        return self.public_key + self.private_key
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'MPCEncryption':
        if len(data) != 64:  # 32 bytes for each key
            raise ValueError("Invalid MPCEncryption data length")
        return cls(data[:32], data[32:])

class TagOffsetCounter:
    def __init__(self, counter: int = 0):
        self.counter = counter
    
    def to_bytes(self) -> bytes:
        return self.counter.to_bytes(8, byteorder='little')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TagOffsetCounter':
        if len(data) != 8:
            raise ValueError("Invalid TagOffsetCounter data length")
        return cls(int.from_bytes(data, byteorder='little'))

class Relay:
    def __init__(self, messages: list = None):
        self.messages = messages or []
    
    def to_bytes(self) -> bytes:
        return json.dumps(self.messages).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Relay':
        return cls(json.loads(data.decode()))

class ServerState:
    def __init__(self, state: dict = None):
        self.state = state or {}
    
    def to_bytes(self) -> bytes:
        return json.dumps(self.state).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ServerState':
        return cls(json.loads(data.decode()))

# Load the Rust dynamic library
# Adjust the library name based on your OS:
# - Linux: libmpc_lib.so
# - macOS: libmpc_lib.dylib
# - Windows: mpc_lib.dll
def load_rust_library(lib_path: str = None):
    if lib_path is None:
        # Check environment variable first
        lib_path = os.environ.get('RUST_LIB_PATH')
        
        if lib_path is None:
            # Use the provided absolute path as the default
            lib_path = '/Users/machbluex/Documents/DarkPools-A2A-main/libsl_compute.dylib'
            if not os.path.exists(lib_path):
                raise RuntimeError(
                    f"Could not find Rust library at {lib_path}. Please specify the path or set the RUST_LIB_PATH environment variable."
                )
    
    print(f"Loading library from: {lib_path}")
    return ctypes.CDLL(lib_path)

# Define ctypes structures matching the Rust FFI structs
class FFI_BinaryArithmeticShare(ctypes.Structure):
    _fields_ = [
        ("value1", ctypes.c_ubyte * FIELD_SIZE_BYTES),
        ("value2", ctypes.c_ubyte * FIELD_SIZE_BYTES),
    ]

class FFI_BinaryShare(ctypes.Structure):
    _fields_ = [
        ("value1", ctypes.c_ubyte),
        ("value2", ctypes.c_ubyte),
    ]

class FFI_CompareGEResult(ctypes.Structure):
    _fields_ = [
        ("success", ctypes.c_ubyte),
        ("result", FFI_BinaryShare),
        ("error_msg_ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("error_msg_len", ctypes.c_size_t),
    ]

class BinaryArithmeticShare:
    """Python wrapper for BinaryArithmeticShare"""
    def __init__(self, value1: bytes = None, value2: bytes = None):
        if value1 is None:
            value1 = bytes(FIELD_SIZE_BYTES)
        if value2 is None:
            value2 = bytes(FIELD_SIZE_BYTES)
        
        if len(value1) != FIELD_SIZE_BYTES or len(value2) != FIELD_SIZE_BYTES:
            raise ValueError(f"Values must be exactly {FIELD_SIZE_BYTES} bytes")
        
        self.value1 = value1
        self.value2 = value2
    
    def to_ffi(self) -> FFI_BinaryArithmeticShare:
        """Convert to FFI-compatible structure"""
        ffi_share = FFI_BinaryArithmeticShare()
        for i in range(FIELD_SIZE_BYTES):
            ffi_share.value1[i] = self.value1[i]
            ffi_share.value2[i] = self.value2[i]
        return ffi_share
    
    def get_value1_as_int(self) -> int:
        """Get value1 as an integer"""
        return int.from_bytes(self.value1, byteorder='little', signed=False)
    
    def get_value2_as_int(self) -> int:
        """Get value2 as an integer"""
        return int.from_bytes(self.value2, byteorder='little', signed=False)
    
    @classmethod
    def from_int(cls, value: int, party_index: int) -> 'BinaryArithmeticShare':
        """Create a share from an integer value for a specific party"""
        # Convert integer to bytes (little-endian)
        value_bytes = value.to_bytes(FIELD_SIZE_BYTES, byteorder='little', signed=False)
        
        if party_index == 0:
            return cls(value_bytes, value_bytes)
        elif party_index == 1:
            return cls(value_bytes, bytes(FIELD_SIZE_BYTES))
        else:
            return cls(bytes(FIELD_SIZE_BYTES), bytes(FIELD_SIZE_BYTES))
    
    @classmethod
    def from_int_ffi(cls, value: int, party_index: int, rust_lib) -> 'BinaryArithmeticShare':
        """Create a share from an integer value using the Rust FFI function"""
        ffi_share = rust_lib.create_binary_arithmetic_share(value, party_index)
        value1 = bytes(ffi_share.value1)
        value2 = bytes(ffi_share.value2)
        return cls(value1, value2)

class BinaryShare:
    """Python wrapper for BinaryShare"""
    def __init__(self, value1: bool, value2: bool):
        self.value1 = value1
        self.value2 = value2
    
    @classmethod
    def from_ffi(cls, ffi_share: FFI_BinaryShare) -> 'BinaryShare':
        """Create from FFI structure"""
        return cls(bool(ffi_share.value1), bool(ffi_share.value2))

class CompareGEWrapper:
    """Wrapper for the compare_ge FFI functions"""
    
    def __init__(self, lib_path: str = None):
        self.rust_lib = self._load_rust_library(lib_path)
        self._setup_functions()
    
    def _load_rust_library(self, lib_path: str = None) -> ctypes.CDLL:
        """Load the Rust dynamic library"""
        if lib_path is None:
            # Check environment variable first
            lib_path = os.environ.get('RUST_LIB_PATH')
            
            if lib_path is None:
                # Use the provided absolute path as the default
                lib_path = '/Users/machbluex/Documents/DarkPools-A2A-main/libsl_compute.dylib'
                if not os.path.exists(lib_path):
                    raise RuntimeError(
                        f"Could not find Rust library at {lib_path}. Please specify the path or set the RUST_LIB_PATH environment variable."
                    )
        
        print(f"Loading library from: {lib_path}")
        return ctypes.CDLL(lib_path)
    
    def _setup_functions(self):
        """Set up function signatures for the Rust FFI functions"""
        # Setup compare_ge_simple_ffi
        self.rust_lib.compare_ge_simple_ffi.argtypes = [
            ctypes.POINTER(FFI_BinaryArithmeticShare),
            ctypes.POINTER(FFI_BinaryArithmeticShare),
        ]
        self.rust_lib.compare_ge_simple_ffi.restype = FFI_BinaryShare
        
        # Setup create_binary_arithmetic_share
        self.rust_lib.create_binary_arithmetic_share.argtypes = [
            ctypes.c_uint64,
            ctypes.c_size_t,
        ]
        self.rust_lib.create_binary_arithmetic_share.restype = FFI_BinaryArithmeticShare
        
        # Setup get_share_value1 and get_share_value2
        self.rust_lib.get_share_value1.argtypes = [ctypes.POINTER(FFI_BinaryArithmeticShare)]
        self.rust_lib.get_share_value1.restype = ctypes.c_uint64
        
        self.rust_lib.get_share_value2.argtypes = [ctypes.POINTER(FFI_BinaryArithmeticShare)]
        self.rust_lib.get_share_value2.restype = ctypes.c_uint64
    
    def compare_ge_simple(self, x: BinaryArithmeticShare, y: BinaryArithmeticShare) -> BinaryShare:
        """Compare two BinaryArithmeticShares using the simple FFI function"""
        x_ffi = x.to_ffi()
        y_ffi = y.to_ffi()
        
        result = self.rust_lib.compare_ge_simple_ffi(
            ctypes.byref(x_ffi),
            ctypes.byref(y_ffi)
        )
        
        return BinaryShare.from_ffi(result)
    
    def get_share_value1(self, share: BinaryArithmeticShare) -> int:
        """Get value1 from a BinaryArithmeticShare using FFI"""
        ffi_share = share.to_ffi()
        return self.rust_lib.get_share_value1(ctypes.byref(ffi_share))
    
    def get_share_value2(self, share: BinaryArithmeticShare) -> int:
        """Get value2 from a BinaryArithmeticShare using FFI"""
        ffi_share = share.to_ffi()
        return self.rust_lib.get_share_value2(ctypes.byref(ffi_share))

def example_usage():
    """Example usage of the CompareGEWrapper"""
    print("\n=== Simple Comparison Example ===")
    
    # Create wrapper
    wrapper = CompareGEWrapper()
    
    # Create shares for x = 20 and y = 10
    x = BinaryArithmeticShare.from_int(20, 0)
    y = BinaryArithmeticShare.from_int(10, 0)
    
    # Compare x >= y
    result = wrapper.compare_ge_simple(x, y)
    print(f"x >= y: value1={result.value1}, value2={result.value2}")
    
    # Compare y >= x
    result = wrapper.compare_ge_simple(y, x)
    print(f"x >= y: value1={result.value1}, value2={result.value2}")
    
    print("\n=== Using FFI-based share creation ===")
    # Create shares using FFI
    x = BinaryArithmeticShare.from_int_ffi(20, 0, wrapper.rust_lib)
    y = BinaryArithmeticShare.from_int_ffi(10, 0, wrapper.rust_lib)
    
    # Compare x >= y
    result = wrapper.compare_ge_simple(x, y)
    print(f"x >= y: value1={result.value1}, value2={result.value2}")
    
    print("\nExtracting values from shares:")
    print(f"x.value1 = {wrapper.get_share_value1(x)} (Python method)")
    print(f"x.value1 = {x.get_value1_as_int()} (FFI method)")
    print(f"x.value2 = {wrapper.get_share_value2(x)} (Python method)")
    print(f"x.value2 = {x.get_value2_as_int()} (FFI method)")

if __name__ == "__main__":
    example_usage()