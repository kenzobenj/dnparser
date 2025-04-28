import pefile
import uuid
import math
import dn_constants as const

class Stream:
    def __init__(self, name, size, rva, phys_addr):
        self.name = name
        self.size = size
        self.rva = rva
        self.phys_addr = phys_addr

class Metadata:

    def __init__(self):
        self.has_extra = False
        self.tables = []
        self.index_sizes = {}
        self.table_rowcounts = {}

    def get_table_size(self, table_name):
        return self.table_rowcounts[table_name] * const.ROW_SIZE_FUNCS[table_name](self.index_sizes)

    def get_row_size(self, table_name):
        return const.ROW_SIZE_FUNCS[table_name](self.index_sizes)
    
    def get_addr_in_table(self, metadata_stream_rva, tablename: str, row=1):        
        offset = metadata_stream_rva + 24 + (4 * len(self.tables))
        for table in self.tables:
            if table == tablename:
                break
            offset += self.get_table_size(table)
        row_size = self.get_row_size(tablename)        
        offset += (row - 1) * row_size
        return offset        

    def parse(self, pe, streams):
        metadata_stream = streams.get('#~') if '#~' in streams else streams.get('#-')
        if not metadata_stream:
            print('!! No metadata stream. Cannot continue processing. !!')
            return
        if metadata_stream.name == '#-':
            print('!! Cannot process unoptimized metadata. !!')
            return
        offsetSizeFlags = int.from_bytes(pe.get_data(metadata_stream.rva + 4 + 1 + 1, 1), byteorder = 'little')        
        self.parse_stream_offset_sizes(offsetSizeFlags)
        tableFlags = pe.get_qword_at_rva(metadata_stream.rva + 4 + 1 + 1 + 1 + 1)    
        self.parse_tables(tableFlags, pe, metadata_stream)

    def parse_tables(self, tableFlags, pe, metadata_stream):        
        for flag, name in const.METADATA_TABLE_FLAGS.items():
            self.table_rowcounts[name] = 0            
            if flag & tableFlags == flag:
                self.tables.append(name)  
        start = metadata_stream.rva + 24
        offset = 0
        i = 0            
        for table in self.tables:        
            row_count = pe.get_dword_at_rva(start + (4 * i))        
            self.table_rowcounts[table] = row_count                                    
            i += 1               
        for table, row_count in self.table_rowcounts.items():
            self.index_sizes[table] = 2 if row_count < 2 ** 16 else 4
        self.index_sizes['HasCustomAttribute'] = self.calculate_coded_index_size(const.HAS_CUSTOM_ATTRIBUTE)
        self.index_sizes['TypeDefOrRef'] = self.calculate_coded_index_size(const.TYPE_DEF_OR_REF)
        self.index_sizes['HasConstant'] = self.calculate_coded_index_size(const.HAS_CONSTANT)
        self.index_sizes['HasFieldMarshal'] = self.calculate_coded_index_size(const.HAS_FIELD_MARSHAL)
        self.index_sizes['HasDeclSecurity'] = self.calculate_coded_index_size(const.HAS_DECL_SECURITY)
        self.index_sizes['MemberRefParent'] = self.calculate_coded_index_size(const.MEMBER_REF_PARENT)
        self.index_sizes['HasSemantics'] = self.calculate_coded_index_size(const.HAS_SEMANTICS)
        self.index_sizes['MethodDefOrRef'] = self.calculate_coded_index_size(const.METHOD_DEF_OR_REF)
        self.index_sizes['MemberForwarded'] = self.calculate_coded_index_size(const.MEMBER_FORWARDED)
        self.index_sizes['Implementation'] = self.calculate_coded_index_size(const.IMPLEMENTATION)
        self.index_sizes['CustomAttributeType'] = self.calculate_coded_index_size(const.CUSTOM_ATTRIBUTE_TYPE)
        self.index_sizes['ResolutionScope'] = self.calculate_coded_index_size(const.RESOLUTION_SCOPE)
        self.index_sizes['TypeOrMethodDef'] = self.calculate_coded_index_size(const.TYPE_OR_METHOD_DEF)  
        

    def calculate_coded_index_size(self, table_list):
        n = len(table_list)                
        row_max = 2 ** (16 - math.ceil(math.log2(n)))                
        for table, row_count in self.table_rowcounts.items():                                    
            if table in table_list and row_count >= row_max:             
                return 4
        return 2
            
    def parse_stream_offset_sizes(self, offsetSizeFlags):
        strings = 0x01
        guids = 0x02
        blob = 0x04
        extra = 0x40 
        self.index_sizes['#Strings'] = 4 if offsetSizeFlags & strings else 2
        self.index_sizes['#GUID'] = 4 if offsetSizeFlags & guids else 2
        self.index_sizes['#Blob'] = 4 if offsetSizeFlags & blob else 2        
        if offsetSizeFlags & extra == extra:
            self.has_extra = True