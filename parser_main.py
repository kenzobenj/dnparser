import pefile
import uuid
import math
import metadata_util as mu
import dn_constants as const
import argparse

def print_divider():
    print('-------------------------------------------------------------------------------------')

def print_header(header):
    print(f'{header:^85}\n')    
        
def is_dotnet(pe: pefile.PE):    
    # Find the CLR dir in OPTIONAL_HEADER.  Validate that it has a VA and size
    clr_header_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]    
    return clr_header_entry.VirtualAddress > 0

def find_metadata(pe: pefile.PE):
    print_divider()
    print_header('Locating Metadata')
    clr_header_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    print(f'CLR header RVA: {clr_header_entry.VirtualAddress:#04X}')
    metadata_virtual_address = pe.get_dword_at_rva(rva = clr_header_entry.VirtualAddress + 4 + 2 + 2)
    metadata_size = pe.get_dword_at_rva(rva = clr_header_entry.VirtualAddress + 4 + 2 + 2 + 4)
    print(f'Metadata header RVA: {metadata_virtual_address:#04X}')
    print(f'Metadata size: {metadata_size:#04X}')
    bsbj_bytes = pe.get_data(metadata_virtual_address, 4)
    print(f'Metadata magic bytes: \n   - Hex: {bsbj_bytes.hex()} \n   - ASCII: {bsbj_bytes.decode("ascii", errors="replace")}')    
    if bsbj_bytes.decode("ascii", errors="replace") != 'BSJB':
        print('Unexpected magic bytes. Something went wrong.')
        return -1
    return metadata_virtual_address, metadata_size

def get_padding(data_size, block_size):        
    return (-data_size) % block_size
    
def get_streams(pe: pefile.PE, metadata_rva):
    # 4-byte magic number, major & minor versions (2 bytes each), 4 bytes reserved, len of ascii clr version (dword). ascii clr version, null-padded to 4-byte boundary, 2 bytes reserved, then # of streams
    ver_str_len = pe.get_dword_at_rva(metadata_rva + 12)
    #print(f'Version string is {int.from_bytes(ver_str_len, "little")} bytes long.')
    #print(f'Version string is {ver_str_len:#04X} bytes long.')
    padding = get_padding(ver_str_len, 4)
    num_streams = pe.get_word_at_rva(metadata_rva + 12 + 4 + ver_str_len + padding + 2)
    #print(f'Number of streams: {num_streams:#04X}')
    stream_hdrs_start = metadata_rva + 12 + 4 + ver_str_len + padding + 4    
    next_stream_hdr = stream_hdrs_start
    streams = {}
    # Create a table of: stream name, stream size, stream RVA, stream Phys Addr
    for i in range(num_streams):
        rva = metadata_rva + pe.get_dword_at_rva(next_stream_hdr)
        phys_addr = pe.get_physical_by_rva(rva)
        size = pe.get_dword_at_rva(next_stream_hdr + 4)
        name = pe.get_string_at_rva(next_stream_hdr + 8)        
        name_size = len(name) + 1 #null terminated        
        padding = get_padding(name_size, 4)                
        streams[name.decode()] = mu.Stream(name.decode(), size, rva, phys_addr)
        next_stream_hdr = next_stream_hdr + 8 + name_size + padding
    print_header('STREAMS')
    print("{:<20} {:<20} {:<20} {:<20}".format('Stream','Size','RVA', 'Physical Address'))
    for name, stream in streams.items():        
        print(f'{str(name):<20} {stream.size:<#20X} {stream.rva:<#20X} {stream.phys_addr:<#20X}')
    return streams

def dump_guid_stream(pe: pefile.PE, streams, index = 1, all = True):
    if '#GUID' not in streams:
        print(f'No #GUID stream to dump. Streams: {streams.keys()}')
        return
    guids = streams.get('#GUID')
    res = []    
    if all:
        count = guids.size // 16        
        i = 0
        while i < count:        
            res.append(pe.get_data(guids.rva + (16 * i), 16))
            i += 1
        print_header('#GUID')
    else:
        res.append(pe.get_data(guids.rva + (16 * (index - 1)), 16)) # indexes start at 1 not 0
    print("{:<40} {:<40}".format('Hex','UUID'))
    for guid_val in res:
        print(f'{guid_val.hex():<40} {uuid.UUID(bytes_le=guid_val)}')        
    print_divider()
        
    
def get_mvid_by_metadata(pe: pefile.PE, streams, metadata_stream, metadata: mu.Metadata):                  
    if 'Module' not in metadata.tables:
        print("No module table. Can't grab MVID from there so dumping #GUIDS instead.")
        dump_guid_stream(pe, streams)
        return    
    module_table_addr = metadata_stream.rva + 24 + (4 * len(metadata.tables))    
    print_header('Module Name')
    mname_index = int.from_bytes(pe.get_data(module_table_addr + 2, metadata.index_sizes['#Strings']), byteorder = 'little') # Module name comes after generation ID 
    name = pe.get_string_at_rva(streams['#Strings'].rva + mname_index)
    print(name.decode())
    print_divider()
    mvid_addr = pe.get_data(module_table_addr + 2 + metadata.index_sizes['#Strings'], metadata.index_sizes['#GUID']) # MVID comes after generation ID & name
    mvid_index = int.from_bytes(mvid_addr, byteorder = 'little')
    print_header('MVID')
    dump_guid_stream(pe, streams, index = mvid_index, all = False)        
    
def get_typelib_id(pe: pefile.PE, streams, metadata_stream, metadata: mu.Metadata): 
    typelib_ids = []   
    if 'CustomAttribute' not in metadata.tables or 'Assembly' not in metadata.tables:
        print('Could not find TypeLib ID. Missing CustomAttribute or Assembly metadata tables.')
        return
    offset = metadata_stream.rva + 24 + (4 * len(metadata.tables))
    for table in metadata.tables:
        if table == 'CustomAttribute':
            break
        offset += metadata.get_table_size(table)
    custom_attr_size = metadata.get_table_size('CustomAttribute')
    #print(f'CustomAttribute should be at {offset:#04X}')    
    #print(f'CustomAttribute table size: {custom_attr_size:#04X}')    
    # Now: Parse CA table. Find row with ref to assembly or whatever to indicate it is typelib guid    
    row_size = metadata.get_row_size('CustomAttribute')
    end = offset + custom_attr_size
    parent_size = metadata.index_sizes['HasCustomAttribute']    
    #print(f'Parent index size: {parent_size}')
    #print(f'Row size: {row_size:#04X}')    
    while offset < end:        
        parent_index = pe.get_data(offset, parent_size)        
        index_val = int.from_bytes(parent_index, byteorder='little')
        parent_tag = index_val & 0x1F # HasCustomAttribute tag encoded with 5 bits
        row_id = index_val >> math.ceil(math.log2(len(const.HAS_CUSTOM_ATTRIBUTE)))
        if parent_tag > len(const.HAS_CUSTOM_ATTRIBUTE) - 1:
            print(f'Uh oh did not get valid tag for HasCustomAttribute: {parent_tag}')   
            return     
        elif const.HAS_CUSTOM_ATTRIBUTE[parent_tag] == 'Assembly': # This is a potential TypeLib ID reference in CustomAttribute
            #print(f'Found potential TypeLib ID. Table: {const.HAS_CUSTOM_ATTRIBUTE[parent_tag]} Row: {row_id}')    
            # Parse Type column to find the correlated row in MemberRef     could it be MethodDef too??
            type_index =  pe.get_data(offset + parent_size, metadata.index_sizes['CustomAttributeType'])
            type_index_val = int.from_bytes(type_index, byteorder='little')
            type_tag = type_index_val & 0x7 # CustomAttributeType tag encoded with 3 bits
            type_table = const.CUSTOM_ATTRIBUTE_TYPE[type_tag]            
            if  type_table == 'MemberRef': # TODO if MethodDef, resolve the row, then its owning TypeDef instead
                # Read the row from MemberRef to grab the MemberRefParent index
                type_row_id = type_index_val >> math.ceil(math.log2(len(const.CUSTOM_ATTRIBUTE_TYPE)))
                #print(f'Type tag: {type_table} Row: {type_row_id}')
                type_row_addr = metadata.get_addr_in_table(metadata_stream.rva, type_table, type_row_id)                            
                mrp_index = int.from_bytes(pe.get_data(type_row_addr, metadata.index_sizes['MemberRefParent']), byteorder='little')
                mrp_tag = mrp_index & 0x7 # MemberRefParent tag encoded with 3 bits  
                # Grab the name from the TypeRef entry
                if mrp_tag < len(const.MEMBER_REF_PARENT):
                    mrp_table = const.MEMBER_REF_PARENT[mrp_tag]
                    if  mrp_table == 'TypeRef':
                        mrp_row_id = mrp_index >> math.ceil(math.log2(len(const.MEMBER_REF_PARENT)))
                        #print(f'Class tag: {mrp_table} Row: {mrp_row_id}')
                        mrp_row_addr = metadata.get_addr_in_table(metadata_stream.rva, mrp_table, mrp_row_id)
                        typename_addr = mrp_row_addr + metadata.index_sizes['ResolutionScope']
                        typename_str_addr = int.from_bytes(pe.get_data(typename_addr, metadata.index_sizes['#Strings']), byteorder='little') + streams['#Strings'].rva
                        typename = pe.get_string_at_rva(typename_str_addr)
                        typenamespace_addr = mrp_row_addr + metadata.index_sizes['ResolutionScope'] + metadata.index_sizes['#Strings']
                        typenamespace_str_addr = int.from_bytes(pe.get_data(typenamespace_addr, metadata.index_sizes['#Strings']), byteorder='little') + streams['#Strings'].rva
                        typenamespace = pe.get_string_at_rva(typenamespace_str_addr)                                                
                        if typename.decode() == 'GuidAttribute' and typenamespace.decode() == 'System.Runtime.InteropServices':
                            #Parse Value column of the row in CustomAttribute (should be the TypeLib ID GUID)
                            value_index = pe.get_data(offset + parent_size + metadata.index_sizes['CustomAttributeType'], metadata.index_sizes['#Blob'])
                            value = pe.get_data(streams['#Blob'].rva + int.from_bytes(value_index, byteorder='little'), 0x2A)
                            typelib_ids.append(value[4:-2]) # GUID in #Blob will start with 0x29 for size, 0x0001 prolog, 0x24 str size, GUID val, 0x0000 NumNamed (no named arguments)                                                        
                else:
                    print(f'Something went wrong. Class tag isn\'t correct: {mrp_tag}')
                    return
        offset += row_size  
    print_header('TypeLib ID')                          
    if len(typelib_ids) == 0:
        print('Could not identify TypeLib ID.')
        return
    elif len(typelib_ids) > 1:
        print('Identified multiple TypeLib IDs. Something is strange.')
    for typelibid in typelib_ids:
        print(typelibid.decode())
    
                

def extract_guids(pe: pefile.PE, streams: list[mu.Stream], metadata: mu.Metadata):
    if streams.get('#GUID') == None:
        print('No #GUID stream, something went wrong.')
        return          
    metadata_stream = streams.get('#~') if '#~' in streams else streams.get('#-')    
    if metadata_stream:
        get_mvid_by_metadata(pe, streams, metadata_stream, metadata)
        if not streams.get('#~'):
            print('Skipping TypeLib ID. Cannot process unoptimized metadata.')
        elif streams.get('#Blob'):
            get_typelib_id(pe, streams, metadata_stream, metadata)
        else:
            print('Cannot identify TypeLib ID - missing #Blob stream.') 
    else:
        print('Cannot identify MVID - missing metadata stream (#~ or #-). Dumping all values from #GUIDS instead.')        
        dump_guid_stream(pe, streams)   

def check_for_oddities(pe: pefile.PE, streams: list[mu.Stream], metadata: mu.Metadata):       
    expected_stream_len = 5
    expected_streams = ['#Strings', '#US', '#Blob', '#GUID', '#-', '#~']
    print_divider()
    print_header('Notable Irregularities')
    found_streams = streams.keys()
    if strlen := len(found_streams) != expected_stream_len:
        print(f'Expected {expected_stream_len} streams. Found {strlen}.')
    if len(set(found_streams)) != expected_stream_len: # Don't think this is possible
        print('There are duplicate stream names.')
    if '#-' in found_streams and '#~' in found_streams:
        print('Found both #- and #~ metadata streams.')
    unknown = [x for x in found_streams if x not in expected_streams]
    if unknown:
        print(f'Nonstandard streams: {unknown}')
    if mod_rows := metadata.table_rowcounts['Module'] != 1:
        print(f'More than one row in Module metadata table. Count: {mod_rows}')
    if assembly_rows := metadata.table_rowcounts['Assembly'] != 1:
        print(f'More than one row in Assembly metadata table. Count: {assembly_rows}')
 
def get_assembly_name(pe: pefile.PE, streams: list[mu.Stream], metadata: mu.Metadata):
    if 'Assembly' not in metadata.tables:
        print('Could not find assembly name. Missing Assembly metadata table.')
        return
    metadata_stream = streams.get('#~') if '#~' in streams else streams.get('#-')  
    if not metadata_stream:
        print('No metadata stream identified. Cannot extract assembly details.')  
        return
    offset = metadata_stream.rva + 24 + (4 * len(metadata.tables))
    for table in metadata.tables:
        if table == 'Assembly':
            break
        offset += metadata.get_table_size(table)             
    # Assembly should have 1 row    
    print_header('Assembly Details')
    version_bytes = pe.get_data(offset + 4, 8)   
    version = f'{int.from_bytes(version_bytes[:2], byteorder="little")}.{int.from_bytes(version_bytes[2:4], byteorder="little")}.{int.from_bytes(version_bytes[4:6], byteorder="little")}.{int.from_bytes(version_bytes[6:], byteorder="little")}'    
    name_index = offset + 4 + 4 * 2 + 4 + metadata.index_sizes['#Blob']
    name_index_val = int.from_bytes(pe.get_data(name_index, metadata.index_sizes['#Strings']), byteorder='little')
    name_address = streams['#Strings'].rva + name_index_val    
    name = pe.get_string_at_rva(name_address).decode()
    print(f'Name: {name}')
    print(f'Version: {version}')
    print(f'Version Hex: {version_bytes.hex()}')

parser = argparse.ArgumentParser()
parser.add_argument('file', help='The name of the file to process.')
args = parser.parse_args()
pe = pefile.PE(args.file)
# Make sure it is .NET (probably needs more validation)
if is_dotnet(pe): 
    metadata_rva, metadata_size = find_metadata(pe)
    print_divider()
    streams = get_streams(pe, metadata_rva)
    metadata = mu.Metadata()    
    metadata.parse(pe, streams)    
    print_divider()
    get_assembly_name(pe, streams, metadata)
    print_divider()
    extract_guids(pe, streams, metadata)            
    check_for_oddities(pe, streams, metadata)
    print_divider()
    print_header('YARA Tips')
    print('*  .NET binaries should have 5 standard streams. Any extra or missing?')
    print('\n*  Assembly name and Module name are in the #Strings stream,\n   so they make good strings in rules.')
    print('\n*  Unique Assembly version? Use the hex output.')
    print('\n*  MVID is the module version ID. This changes with recompilation, \n   but can track a sample that has been repacked/modified.\n   This is in the #GUID stream so use the hex output.')
    print('\n*  TypeLib ID is unique per project and robust against recompilation. \n   This is in plaintext, use the string value. \n   NOTE: The fullword modifier will fail here since the value is prepended\n   by its length: 0x24 ($ in ASCII)')
    print_divider()        
else:
    print('Invalid!')


