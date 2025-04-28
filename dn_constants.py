# https://github.com/pan-unit42/dotnetfile/blob/main/dotnetfile/constants.py#L101
METADATA_TABLE_FLAGS = {
    1:                  'Module',
    2:                  'TypeRef',
    4:                  'TypeDef',
    8:                  'FieldPtr',
    16:                 'Field',
    32:                 'MethodPtr',
    64:                 'MethodDef',
    128:                'ParamPtr',
    256:                'Param',
    512:                'InterfaceImpl',
    1024:               'MemberRef',
    2048:               'Constant',
    4096:               'CustomAttribute',
    8192:               'FieldMarshal',
    16384:              'DeclSecurity',
    32768:              'ClassLayout',
    65536:              'FieldLayout',
    131072:             'StandAloneSig',
    262144:             'EventMap',
    524288:             'EventPtr',
    1048576:            'Event',
    2097152:            'PropertyMap',
    4194304:            'PropertyPtr',
    8388608:            'Property',
    16777216:           'MethodSemantics',
    33554432:           'MethodImpl',
    67108864:           'ModuleRef',
    134217728:          'TypeSpec',
    268435456:          'ImplMap',
    536870912:          'FieldRVA',
    1073741824:         'EncLog',
    2147483648:         'EncMap',
    4294967296:         'Assembly',
    8589934592:         'AssemblyProcessor',
    17179869184:        'AssemblyOS',
    34359738368:        'AssemblyRef',
    68719476736:        'AssemblyRefProcessor',
    137438953472:       'AssemblyRefOS',
    274877906944:       'File',
    549755813888:       'ExportedType',
    1099511627776:      'ManifestResource',
    2199023255552:      'NestedClass',
    4398046511104:      'GenericParam',
    8796093022208:      'MethodSpec',
    17592186044416:     'GenericParamConstraint',
    35184372088832:     'Document',
    70368744177664:     'MethodDebugInformation',
    140737488355328:    'LocalScope',
    281474976710656:    'LocalVariable',
    562949953421312:    'LocalConstant',
    1125899906842624:   'ImportScope',
    2251799813685248:   'StateMachineMethod',
    4503599627370496:   'CustomDebugInformation'
}

HAS_CUSTOM_ATTRIBUTE = ['MethodDef', 'Field', 'TypeRef', 'TypeDef', 'Param', 'InterfaceImpl', 'MemberRef', 'Module', 'DeclSecurity', 'Property', 'Event', 'StandAloneSig', 'ModuleRef', 'TypeSpec', 'Assembly', 'AssemblyRef', 'File', 'ExportedType', 'ManifestResource', 'GenericParam', 'GenericParamConstraint', 'MethodSpec']

TYPE_DEF_OR_REF = ['TypeDef','TypeRef','TypeSpec']

HAS_CONSTANT = ['Field','Param','Property']

HAS_FIELD_MARSHAL = ['Field','Param']

HAS_DECL_SECURITY = ['TypeDef','MethodDef','Assembly']

MEMBER_REF_PARENT = ['TypeDef','TypeRef','ModuleRef','MethodDef','TypeSpec']

HAS_SEMANTICS = ['Event','Property']

METHOD_DEF_OR_REF = ['MethodDef','MemberRef']

MEMBER_FORWARDED = ['Field','MethodDef']

IMPLEMENTATION = ['File','AssemblyRef','ExportedType']

CUSTOM_ATTRIBUTE_TYPE = ['NotUsed1', 'NotUsed2', 'MethodDef','MemberRef', 'NotUsed3']

RESOLUTION_SCOPE = ['Module','ModuleRef','AssemblyRef','TypeRef']

TYPE_OR_METHOD_DEF = ['TypeDef','MethodDef']

#If e is a simple index into a table with index i, it is stored using 2 bytes if table i has
#less than 216 rows, otherwise it is stored using 4 bytes.
# Add all simple & coded indexes to the size list

ROW_SIZE_FUNCS = {
    'Module': lambda index_sizes: 2 + index_sizes['#Strings'] + 3 * index_sizes['#GUID'],
    'TypeRef': lambda index_sizes: index_sizes['ResolutionScope'] + 2 * index_sizes['#Strings'],
    'TypeDef': lambda index_sizes: 4 + 2 * index_sizes['#Strings'] + index_sizes['TypeDefOrRef'] + index_sizes['Field'] + index_sizes['MethodDef'],
    'Field': lambda index_sizes: 2 + index_sizes['#Strings'] + index_sizes['#Blob'],
    'MethodDef': lambda index_sizes: 4 + 2 + 2 + index_sizes['#Strings'] + index_sizes['#Blob'] + index_sizes['Param'],
    'Param': lambda index_sizes: 2 + 2 + index_sizes['#Strings'],
    'InterfaceImpl': lambda index_sizes: index_sizes['TypeDef'] + index_sizes['TypeDefOrRef'],
    'MemberRef': lambda index_sizes: index_sizes['MemberRefParent'] + index_sizes['#Strings'] + index_sizes['#Blob'],
    'Constant': lambda index_sizes: 1 + 1 + index_sizes['HasConstant'] + index_sizes['#Blob'],    
    'CustomAttribute': lambda index_sizes: index_sizes['HasCustomAttribute'] + index_sizes['CustomAttributeType'] + index_sizes['#Blob'],
    'FieldMarshal': lambda index_sizes: index_sizes['HasFieldMarshal'] + index_sizes['#Blob'],
    'DeclSecurity': lambda index_sizes: 2 + index_sizes['HasDeclSecurity'] + index_sizes['#Blob'],
    'ClassLayout': lambda index_sizes: 2 + 4 + index_sizes['TypeDef'],
    'FieldLayout': lambda index_sizes: 4 + index_sizes['Field'],
    'StandAloneSig': lambda index_sizes: index_sizes['#Blob'],
    'EventMap': lambda index_sizes: index_sizes['TypeDef'] + index_sizes['Event'],
    'Event': lambda index_sizes: 2 + index_sizes['#Strings'] + index_sizes['TypeDefOrRef'],
    'PropertyMap': lambda index_sizes: index_sizes['TypeDef'] + index_sizes['Property'],
    'Property': lambda index_sizes: 2 + index_sizes['#Strings'] + index_sizes['#Blob'],
    'MethodSemantics': lambda index_sizes: 2 + index_sizes['MethodDef'] + index_sizes['HasSemantics'],
    'MethodImpl': lambda index_sizes: index_sizes['TypeDef'] + 2 * index_sizes['MethodDefOrRef'],
    'ModuleRef': lambda index_sizes: index_sizes['#Strings'],
    'TypeSpec': lambda index_sizes: index_sizes['#Blob'],
    'ImplMap': lambda index_sizes: 2 + index_sizes['MemberForwarded'] + index_sizes['#Strings'] + index_sizes['ModuleRef'],
    'FieldRVA': lambda index_sizes: 4 + index_sizes['Field'],
    'Assembly': lambda index_sizes: 4 + 2 + 2 + 2 + 2 + 4 + index_sizes['#Blob'] + 2 * index_sizes['#Strings'],
    'AssemblyProcessor': lambda index_sizes: 4 + index_sizes['AssemblyRef'],
    'AssemblyOS': lambda index_sizes: 4 + index_sizes['AssemblyRef'], 
    'AssemblyRef': lambda index_sizes: 4 * 2 + 4 + index_sizes['#Blob'] + index_sizes['#Strings'] + index_sizes['#Strings'] + index_sizes['#Blob'],
    'AssemblyRefProcessor': lambda index_sizes: 4 + index_sizes['AssemblyRef'],
    'AssemblyRefOS': lambda index_sizes: 4 + 4 + 4 + index_sizes['AssemblyRef'],
    'File': lambda index_sizes: 4 + index_sizes['#Strings'] + index_sizes['#Blob'],
    'ExportedType': lambda index_sizes: 4 + 4 + index_sizes['#Strings'] + index_sizes['#Strings'] + index_sizes['Implementation'],
    'ManifestResource': lambda index_sizes: 4 + 4 + index_sizes['#Strings'] + index_sizes['Implementation'],
    'NestedClass': lambda index_sizes: index_sizes['TypeDef'] + index_sizes['TypeDef']
    # Need to do the rest, but for now all we really need is up to AssemblyRef
}