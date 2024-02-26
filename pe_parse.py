import struct
from capstone import *

SECTION_HEADER_SIZE = 40
FILE_HEADER_OFFSET = 4
SECTION_NAME_SIZE = 8
HEADER_SIG_SIZE = 4
E_LFANEW_OFFSET = 0x3c
OPTIONA_HEADER_OFFSET_SIZE = 16
COFF_HEADER_SIZE = 20
ADDRESS_OF_ENTRY_POINT = 20

class PEFormatError(Exception):
    """Exception handler for common PE header errors"""
    pass

class PESectionHeader:
    def __init__(self, pe_header_base):
        self.name = pe_header_base[0:8].decode().rstrip('\x00')

        if self.name[0] not in ['.', '_']:
            raise PEFormatError("Invalid section name")

        """
        typedef struct _IMAGE_SECTION_HEADER {
            BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
            union {
                    DWORD   PhysicalAddress;
                    DWORD   VirtualSize;
            } Misc;
            DWORD   VirtualAddress;
            DWORD   SizeOfRawData;
            DWORD   PointerToRawData;
            DWORD   PointerToRelocations;
            DWORD   PointerToLinenumbers;
            WORD    NumberOfRelocations;
            WORD    NumberOfLinenumbers;
            DWORD   Characteristics;
        } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
        """
        # https://docs.python.org/3/library/struct.html
        (
            self.virtual_size,
            self.virtual_address,
            self.size_of_raw_data,
            self.pointer_to_raw_data,
            self.pointer_to_relocations,
            self.pointer_to_linenumbers,
            self.number_of_relocations,
            self.number_of_linenumbers,
            self.characteristics
        ) = struct.unpack('<IIIIIIHHI', pe_header_base[SECTION_NAME_SIZE : SECTION_HEADER_SIZE])

def log_function_call(func):
    def wrapper(*args, **kwargs):
        print(f"Calling function: {func.__name__} with args {args} kwargs {kwargs}")
        result = func(*args, *kwargs)
        print(f"{func.__name__} return {result}")
        return result
    return wrapper

class PEParse:
    def read_file(self) -> bytes:
        try:
            with open(self.filepath, 'rb') as file:
                rawbin = file.read()
        except FileNotFoundError:
            raise
        except PermissionError:
            raise
        except IOError as e:
            raise
        return rawbin
    
    @log_function_call
    def parse_headers(self) -> int:
        """This function will validate headers, and on success, will return the physical offset to the text segment"""

        # Set the self.pe_header_base
        self.jump_to_pe_header()

        # Parse IMAGE_SECTION_HEADER into list
        self.parse_section_headers(self.pe_header)

        # List sections
        self.list_section_info(self.section_headers)        

        # Print assembly 
        self.print_text_segment_assembly(self.pe_header, self.rawbin, self.section_headers)
        
        return 0  

    @log_function_call
    def print_text_segment_assembly(self, pe_base, raw_bin, segments):
        """
        Find .text and print assembly out
        typedef struct _IMAGE_OPTIONAL_HEADER {
            //
            // Standard fields.
            //

            WORD    Magic;
            BYTE    MajorLinkerVersion;
            BYTE    MinorLinkerVersion;
            DWORD   SizeOfCode;
            DWORD   SizeOfInitializedData;
            DWORD   SizeOfUninitializedData;
            DWORD   AddressOfEntryPoint; 20
            DWORD   BaseOfCode;
            DWORD   BaseOfData;
        ...};        
        """
        print(f"PEHeader: {pe_base[:16]}")
        address_of_entry_point = struct.unpack("<I", pe_base[ADDRESS_OF_ENTRY_POINT : ADDRESS_OF_ENTRY_POINT + 4])[0]
        print(f'AddressOfEntryPoint: {address_of_entry_point}')

        # This seriously needs to be refactored. 
        for curr_header in self.section_headers:
            if curr_header.name == '.text':
                print(f"Found text segment, size: {curr_header.size_of_raw_data}")
                text_code_raw = raw_bin[curr_header.pointer_to_raw_data : curr_header.pointer_to_raw_data + curr_header.size_of_raw_data]
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                for i in md.disasm(text_code_raw, curr_header.size_of_raw_data):
                    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")


    @log_function_call
    def list_section_info(self, section_headers):
        for curr_section in section_headers:
            print(f"Name: {curr_section.name}, VirtualSize: {curr_section.virtual_size}, SizeOfRawData: {curr_section.size_of_raw_data}, VirtualAddress: {curr_section.virtual_address}") 
    
    @log_function_call
    def get_number_of_sections(self, pe_header_base) -> int:
        """
        typedef struct _IMAGE_FILE_HEADER {
            WORD    Machine;
            WORD    NumberOfSections;
            DWORD   TimeDateStamp;
            DWORD   PointerToSymbolTable;
            DWORD   NumberOfSymbols;
            WORD    SizeOfOptionalHeader;
            WORD    Characteristics;
        } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
        """
        num_of_section_offset = FILE_HEADER_OFFSET + 2

        # Need to fix this, properly parse COFF, PE and DOS headers!!!
        num_of_sections = struct.unpack('<H', pe_header_base[num_of_section_offset : num_of_section_offset + 2])[0]

        return num_of_sections

    @log_function_call
    def parse_section_headers(self, pe_header_base):     
        # Get number of sections
        self.num_of_sections = self.get_number_of_sections(pe_header_base)
        print(f'Total IMAGE_SECTION_HEADER count: {self.num_of_sections}')

        # Get offset to section headers
        optional_header_size = struct.unpack('<H', pe_header_base[HEADER_SIG_SIZE + OPTIONA_HEADER_OFFSET_SIZE : 4 + 18])[0]
        section_header_offset = HEADER_SIG_SIZE + COFF_HEADER_SIZE + optional_header_size

        section_header_raw = pe_header_base[section_header_offset:]
        
        self.section_headers = []
        #for i in range(0, len(section_header_raw), SECTION_HEADER_SIZE):
        for i in range(0, self.num_of_sections):
            header_data = section_header_raw[i * SECTION_HEADER_SIZE : i * SECTION_HEADER_SIZE + SECTION_HEADER_SIZE]
            curr_header = PESectionHeader(header_data)
            self.section_headers.append(curr_header)

    @log_function_call
    def jump_to_pe_header(self):
        """Jump to the PE header"""
        # Validate MZ sig, fixed size is 64 bytes
        self.mz_header = self.rawbin[:64]    
        print(f'mz_header: {self.mz_header[:32]}')

        if self.mz_header[:HEADER_SIG_SIZE] != b'MZ\x90\x00':
            raise PEFormatError("Invalid MZ header, file is not executable")
        
        # Jump to PE sig through IMAGE_DOS_HEADER->e_lfanew
        # Note: <I indicates a little endian format
        e_lfanew = struct.unpack('<I', self.mz_header[E_LFANEW_OFFSET : E_LFANEW_OFFSET + HEADER_SIG_SIZE])[0]

        # Validate size
        if e_lfanew >= len(self.rawbin):
            raise PEFormatError("IMAGE_DOS_HEADER->e_lfanew is greater than image size")
        
        # Validate PE header, Fixed size of 1024 size, but this is a TODO
        self.pe_header = self.rawbin[e_lfanew:1024]
        print(f'pe_header: {self.pe_header[:32]}')
        if self.pe_header[:4] != b'PE\x00\x00':
            raise PEFormatError("Invalid PE header")
    
    @log_function_call
    def __init__(self, filepath):
        self.filepath = filepath
        self.rawbin = self.read_file()
        self.text_offset = self.parse_headers()
        print(f'filepath: {self.filepath}, PE size: {len(self.rawbin)}')

if __name__ == "__main__":
    print("PEParser is a PE parsing library, import elsewhere...")