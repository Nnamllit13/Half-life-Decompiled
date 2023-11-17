typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef unsigned short    wchar16;
typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

typedef ulong DWORD;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef ushort WORD;

typedef BYTE * LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOW * LPSTARTUPINFOW;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[78];
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef char * va_list;

typedef uint uintptr_t;

typedef struct lconv lconv, *Plconv;

struct lconv {
    char * decimal_point;
    char * thousands_sep;
    char * grouping;
    char * int_curr_symbol;
    char * currency_symbol;
    char * mon_decimal_point;
    char * mon_thousands_sep;
    char * mon_grouping;
    char * positive_sign;
    char * negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t * _W_decimal_point;
    wchar_t * _W_thousands_sep;
    wchar_t * _W_int_curr_symbol;
    wchar_t * _W_currency_symbol;
    wchar_t * _W_mon_decimal_point;
    wchar_t * _W_mon_thousands_sep;
    wchar_t * _W_positive_sign;
    wchar_t * _W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct * pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char * locale;
    wchar_t * wlocale;
    int * refcount;
    int * wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int * lconv_intl_refcount;
    int * lconv_num_refcount;
    int * lconv_mon_refcount;
    struct lconv * lconv;
    int * ctype1_refcount;
    ushort * ctype1;
    ushort * pctype;
    uchar * pclmap;
    uchar * pcumap;
    struct __lc_time_data * lc_time_curr;
    wchar_t * locale_name[6];
};

struct __lc_time_data {
    char * wday_abbr[7];
    char * wday[7];
    char * month_abbr[12];
    char * month[12];
    char * ampm[2];
    char * ww_sdatefmt;
    char * ww_ldatefmt;
    char * ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t * _W_wday_abbr[7];
    wchar_t * _W_wday[7];
    wchar_t * _W_month_abbr[12];
    wchar_t * _W_month[12];
    wchar_t * _W_ampm[2];
    wchar_t * _W_ww_sdatefmt;
    wchar_t * _W_ww_ldatefmt;
    wchar_t * _W_ww_timefmt;
    wchar_t * _W_ww_locale_name;
};

typedef uint size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct * pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t * mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct * _locale_t;

typedef size_t rsize_t;

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _IMAGE_SECTION_HEADER * PIMAGE_SECTION_HEADER;

typedef CHAR * LPCSTR;

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

typedef LONG * PLONG;

typedef CHAR * LPSTR;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[160]; // Actual DOS program
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef int (* FARPROC)(void);

typedef WORD * LPWORD;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef int INT;

typedef BOOL * LPBOOL;

typedef BYTE * PBYTE;

typedef void * LPCVOID;

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_8 IMAGE_RESOURCE_DIR_STRING_U_8, *PIMAGE_RESOURCE_DIR_STRING_U_8;

struct IMAGE_RESOURCE_DIR_STRING_U_8 {
    word Length;
    wchar16 NameString[4];
};

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_34 IMAGE_RESOURCE_DIR_STRING_U_34, *PIMAGE_RESOURCE_DIR_STRING_U_34;

struct IMAGE_RESOURCE_DIR_STRING_U_34 {
    word Length;
    wchar16 NameString[17];
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t * pchLanguage;
    wchar_t * pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct setloc_struct _setloc_struct;

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char * _token;
    wchar_t * _wtoken;
    uchar * _mtoken;
    char * _errmsg;
    wchar_t * _werrmsg;
    char * _namebuf0;
    wchar_t * _wnamebuf0;
    char * _namebuf1;
    wchar_t * _wnamebuf1;
    char * _asctimebuf;
    wchar_t * _wasctimebuf;
    void * _gmtimebuf;
    char * _cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void * _initaddr;
    void * _initarg;
    void * _pxcptacttab;
    void * _tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void * _terminate;
    void * _unexpected;
    void * _translator;
    void * _purecall;
    void * _curexception;
    void * _curcontext;
    int _ProcessingThrow;
    void * _curexcspec;
    void * _pFrameInfoChain;
    _setloc_struct _setloc_data;
    void * _reserved1;
    void * _reserved2;
    void * _reserved3;
    void * _reserved4;
    void * _reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

typedef struct _tiddata * _ptiddata;

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct CatchGuardRN CatchGuardRN, *PCatchGuardRN;

struct CatchGuardRN { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);




undefined4 FUN_3b401000(undefined4 param_1);
undefined4 * __thiscall FUN_3b401020(void *this,byte param_1);
void __cdecl SteamAPI_SetTryCatchCallbacks(undefined param_1);
void __cdecl FUN_3b401060(int param_1);
void __cdecl FUN_3b401080(int **param_1);
void __cdecl FUN_3b4010a0(int param_1);
void __cdecl FUN_3b4010c0(int **param_1);
void __fastcall FUN_3b4010e0(int **param_1);
void __fastcall FUN_3b401130(int **param_1);
undefined4 * __thiscall FUN_3b401180(void *this,exception *param_1);
void __fastcall FUN_3b4011a0(int **param_1);
void __fastcall FUN_3b401220(int param_1);
void __thiscall FUN_3b401260(void *this,undefined4 param_1);
void __thiscall FUN_3b401280(void *this,int *param_1);
void __thiscall FUN_3b4012e0(void *this,int *param_1);
undefined4 * __thiscall FUN_3b401350(void *this,uint *param_1);
void __thiscall FUN_3b4013a0(void *this,int *param_1);
void __thiscall FUN_3b401400(void *this,int *param_1);
void __thiscall FUN_3b401460(void *this,int **param_1,char param_2,int **param_3,int *param_4);
void __thiscall FUN_3b401690(void *this,int **param_1,char param_2,int **param_3,int *param_4);
void __thiscall FUN_3b4018c0(void *this,int **param_1,int **param_2);
void __thiscall FUN_3b401b10(void *this,int **param_1,int **param_2);
void FUN_3b401d60(int *param_1);
void FUN_3b401da0(int *param_1);
void __thiscall FUN_3b401de0(void *this,undefined4 *param_1,int *param_2,char param_3);
void __thiscall FUN_3b401ef0(void *this,undefined4 *param_1,int *param_2);
void __fastcall FUN_3b401f60(int param_1);
void __fastcall FUN_3b401fb0(int param_1);
void __thiscall FUN_3b402000(void *this,int param_1,byte param_2);
void __thiscall FUN_3b402120(void *this,int param_1,byte param_2);
void __thiscall FUN_3b4021f0(void *this,int **param_1);
void __thiscall FUN_3b4022b0(void *this,int **param_1);
void __thiscall FUN_3b402380(void *this,int **param_1,int **param_2,int **param_3);
void __thiscall FUN_3b402420(void *this,int **param_1,int **param_2,int **param_3);
void __thiscall FUN_3b4024c0(void *this,undefined4 *param_1);
void __thiscall FUN_3b402540(void *this,undefined4 *param_1);
void __thiscall FUN_3b4025b0(void *this,HMODULE param_1);
void __thiscall FUN_3b402650(void *this,undefined4 param_1,undefined4 param_2);
void __thiscall FUN_3b402700(void *this,undefined4 *param_1,int *param_2);
void __fastcall FUN_3b402770(void *param_1);
int __fastcall FUN_3b4027d0(int param_1);
void __fastcall FUN_3b402910(void *param_1);
undefined * FUN_3b4029d0(void);
void __cdecl FUN_3b402a30(int param_1,int param_2);
void __cdecl FUN_3b402a70(int **param_1);
void __cdecl FUN_3b402a90(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void __cdecl FUN_3b402ad0(undefined4 param_1,int *param_2,int **param_3);
void __cdecl FUN_3b402b40(undefined4 param_1,undefined4 param_2);
void __cdecl FUN_3b402b60(HMODULE param_1);
undefined4 FUN_3b402b80(void);
undefined4 SteamClient(void);
undefined4 SteamUser(void);
undefined4 SteamFriends(void);
undefined4 SteamUtils(void);
undefined4 SteamMatchmaking(void);
undefined4 SteamMatchmakingServers(void);
undefined4 SteamUserStats(void);
undefined4 SteamApps(void);
undefined4 SteamNetworking(void);
undefined4 SteamRemoteStorage(void);
undefined4 SteamScreenshots(void);
undefined4 SteamHTTP(void);
undefined4 GetHSteamPipe(void);
HMODULE __cdecl FUN_3b402c60(LPCSTR param_1);
undefined4 FUN_3b402d00(void);
undefined4 FUN_3b402d70(void);
bool __cdecl FUN_3b402e00(LPCSTR param_1,LPCSTR param_2,LPBYTE param_3);
void __cdecl FUN_3b402e70(char *param_1);
undefined4 __cdecl FUN_3b402eb0(char *param_1,size_t param_2);
bool __cdecl SteamAPI_RestartAppIfNecessary(int param_1);
undefined4 FUN_3b4031a0(void);
void __cdecl FUN_3b403340(undefined4 param_1,undefined4 param_2);
void FUN_3b4033d0(void);
uint SteamAPI_IsSteamRunning(void);
void __cdecl Steam_RunCallbacks(undefined4 param_1,undefined4 param_2);
void SteamAPI_RunCallbacks(void);
void __cdecl SteamAPI_RegisterCallback(int param_1,int param_2);
void __cdecl SteamAPI_UnregisterCallback(int **param_1);
void __cdecl SteamAPI_RegisterCallResult(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void __cdecl SteamAPI_UnregisterCallResult(undefined4 param_1,int *param_2,int **param_3);
void __cdecl Steam_RegisterInterfaceFuncs(HMODULE param_1);
undefined4 Steam_GetHSteamUserCurrent(void);
void __cdecl SteamAPI_UseBreakpadCrashHandler(char *param_1,char *param_2,char *param_3,undefined param_4,undefined4 param_5,undefined4 param_6);
undefined1 * SteamAPI_GetSteamInstallPath(void);
bool __fastcall FUN_3b403850(int *param_1);
undefined4 GetHSteamUser(void);
void __fastcall FUN_3b4039c0(LPCSTR *param_1);
int __cdecl FUN_3b403b60(HMODULE *param_1,char param_2);
void __cdecl FUN_3b403c80(HMODULE param_1);
void FUN_3b403ca0(void);
void SteamAPI_Shutdown(void);
void SteamAPI_WriteMiniDump(void);
void SteamAPI_SetMiniDumpComment(void);
void __cdecl SteamAPI_SetBreakpadAppID(int param_1);
undefined4 __cdecl FUN_3b403fd0(char param_1);
void SteamAPI_InitSafe(void);
void SteamAPI_Init(void);
undefined4 SteamContentServer(void);
undefined4 SteamContentServerUtils(void);
undefined4 __cdecl SteamContentServer_Init(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void SteamContentServer_Shutdown(void);
void SteamContentServer_RunCallbacks(void);
undefined4 SteamGameServer(void);
undefined4 SteamGameServerUtils(void);
undefined4 SteamGameServerApps(void);
undefined4 SteamGameServerNetworking(void);
undefined4 SteamGameServerStats(void);
undefined4 SteamGameServerHTTP(void);
undefined4 SteamGameServer_GetHSteamPipe(void);
undefined4 SteamGameServer_GetHSteamUser(void);
uint __cdecl FUN_3b404430(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,undefined4 param_6,char param_7);
void __cdecl SteamGameServer_InitSafe(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,undefined4 param_6);
void __cdecl SteamGameServer_Init(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,undefined4 param_6);
void SteamGameServer_Shutdown(void);
void SteamGameServer_RunCallbacks(void);
uint SteamGameServer_BSecure(void);
undefined4 SteamGameServer_GetIPCCallCount(void);
undefined8 SteamGameServer_GetSteamID(void);
undefined4 * __thiscall FUN_3b4047d9(void *this,exception *param_1);
void FUN_3b4047f6(char *param_1);
undefined4 * __thiscall FUN_3b404826(void *this,exception *param_1);
void FUN_3b404843(char *param_1);
undefined4 * __thiscall FUN_3b404873(void *this,exception *param_1);
undefined4 * __thiscall FUN_3b404890(void *this,byte param_1);
void __thiscall std::exception::exception(exception *this,char **param_1,int param_2);
void __thiscall std::exception::_Copy_str(exception *this,char *param_1);
void __thiscall std::exception::_Tidy(exception *this);
exception * __thiscall std::exception::exception(exception *this,char **param_1);
exception * __thiscall std::exception::operator=(exception *this,exception *param_1);
void __fastcall FUN_3b404995(undefined4 *param_1);
undefined4 * __thiscall FUN_3b4049a0(void *this,byte param_1);
exception * __thiscall std::exception::exception(exception *this,exception *param_1);
void __thiscall type_info::~type_info(type_info *this);
void * __thiscall type_info::`scalar_deleting_destructor'(type_info *this,uint param_1);
bool __thiscall type_info::operator==(type_info *this,type_info *param_1);
void FUN_3b404a3d(void *param_1);
void * __cdecl operator_new(uint param_1);
void __CxxThrowException@8(undefined4 param_1,byte *param_2);
void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2);
void FID_conflict:_CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE);
void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2);
undefined4 __cdecl FID_conflict:___CxxFrameHandler3(int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4);
_EXCEPTION_DISPOSITION __cdecl CatchGuardHandler(EHExceptionRecord *param_1,CatchGuardRN *param_2,void *param_3,void *param_4);
int __cdecl _CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7);
_EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(EHExceptionRecord *param_1,TranslatorGuardRN *param_2,void *param_3,void *param_4);
_s_TryBlockMapEntry * __cdecl _GetRangeOfTrysToCheck(_s_FuncInfo *param_1,int param_2,int param_3,uint *param_4,uint *param_5);
undefined4 * __cdecl __CreateFrameInfo(undefined4 *param_1,undefined4 param_2);
undefined4 __cdecl __IsExceptionObjectToBeDestroyed(int param_1);
void __cdecl __FindAndUnlinkFrame(void *param_1);
void * __cdecl _CallCatchBlock2(EHRegistrationNode *param_1,_s_FuncInfo *param_2,void *param_3,int param_4,ulong param_5);
void __cdecl _free(void *_Memory);
void * __cdecl _malloc(size_t _Size);
undefined4 __cdecl __onexit_nolock(undefined4 param_1);
_onexit_t __cdecl __onexit(_onexit_t _Func);
void FUN_3b4050e3(void);
int __cdecl _atexit(_func_4879 *param_1);
int __cdecl __fclose_nolock(FILE *_File);
int __cdecl _fclose(FILE *_File);
void FUN_3b4051d9(void);
void __cdecl FUN_3b4051e1(char *param_1);
void __cdecl FUN_3b4051f7(char *param_1);
char * __cdecl _fgets(char *_Buf,int _MaxCount,FILE *_File);
void FUN_3b405332(void);
FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag);
void FUN_3b4053ec(void);
FILE * __cdecl _fopen(char *_Filename,char *_Mode);
void * __cdecl _memset(void *_Dst,int _Val,size_t _Size);
_LocaleUpdate * __thiscall _LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1);
int __cdecl ___ascii_stricmp(char *_Str1,char *_Str2);
int __cdecl __stricmp_l(char *_Str1,char *_Str2,_locale_t _Locale);
int __cdecl __stricmp(char *_Str1,char *_Str2);
char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count);
int __cdecl __snprintf(char *_Dest,size_t _Count,char *_Format,...);
char * __cdecl _strncat(char *_Dest,char *_Source,size_t _Count);
int __cdecl _fprintf(FILE *_File,char *_Format,...);
void FUN_3b405a67(void);
undefined ** FUN_3b405a71(void);
void __cdecl __lock_file(FILE *_File);
void __cdecl __lock_file2(int _Index,void *_File);
void __cdecl __unlock_file(FILE *_File);
void __cdecl __unlock_file2(int _Index,void *_File);
undefined4 __cdecl _vscan_fn(undefined *param_1,int param_2,undefined4 param_3,undefined4 param_4);
int __cdecl FID_conflict:_sscanf(char *_Src,char *_Format,...);
int __cdecl __strnicmp_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale);
int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount);
undefined4 __CRT_INIT@12(undefined4 crtArgs,int dllState,int mainArgs);
void performCleanup(void);
int __fastcall ___DllMainCRTStartup(int dllArgs,int dllState,undefined4 crtInitArgs);
void entry(undefined4 mainArgs,int securityFlag,int dllMainArgs);
errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src);
size_t __cdecl _strlen(char *_Str);
void __cdecl type_info::_Type_info_dtor(type_info *param_1);
void FUN_3b4061c2(void);
int __cdecl _strcmp(char *_Str1,char *_Str2);
void __cdecl _abort(void);
wchar_t * __cdecl __GET_RTERRMSG(int param_1);
void __cdecl __NMSG_WRITE(int param_1);
void __cdecl __FF_MSGBANNER(void);
void __cdecl FUN_3b406499(undefined4 param_1);
void __cdecl FUN_3b4064a8(undefined4 param_1);
int __cdecl __callnewh(size_t _Size);
undefined4 * __thiscall FUN_3b4064ea(void *this,byte param_1);
undefined4 __cdecl ___TypeMatch(byte *param_1,byte *param_2,uint *param_3);
_ptiddata __cdecl ___FrameUnwindFilter(int **param_1);
void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4);
void FUN_3b406681(void);
void __cdecl ___DestructExceptionObject(int *param_1);
int __cdecl ___AdjustPointer(int param_1,int *param_2);
undefined __cdecl FUN_3b40675e(int param_1);
void FUN_3b4067d4(void *param_1);
void * __cdecl CallCatchBlock(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,_s_FuncInfo *param_4,void *param_5,int param_6,ulong param_7);
void FUN_3b406943(void);
char __cdecl ___BuildCatchObjectHelper(int param_1,int *param_2,uint *param_3,byte *param_4);
void __cdecl ___BuildCatchObject(int param_1,int *param_2,uint *param_3,byte *param_4);
void __cdecl CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,_s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11);
void __cdecl FindHandlerForForeignException(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8);
void __cdecl FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8);
undefined4 * __thiscall FUN_3b4070b4(void *this,exception *param_1);
undefined4 __cdecl ___InternalCxxFrameHandler(int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,uint *param_5,int param_6,EHRegistrationNode *param_7,uchar param_8);
void __fastcall @__security_check_cookie@4(int param_1);
void FUN_3b4071c6(void);
LPVOID ___set_flsgetvalue(void);
void __cdecl __mtterm(void);
void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale);
void FUN_3b4072eb(void);
void FUN_3b4072f4(void);
_ptiddata __cdecl __getptd_noexit(void);
_ptiddata __cdecl __getptd(void);
void __freefls@4(void *param_1);
void FUN_3b4074aa(void);
void FUN_3b4074b6(void);
void __cdecl __freeptd(_ptiddata _Ptd);
int __cdecl __mtinit(void);
void __cdecl terminate(void);
void __cdecl unexpected(void);
void __cdecl _inconsistency(void);
void FUN_3b40772c(void);
void __CallSettingFrame@12(undefined4 param_1,undefined4 param_2,int param_3);
int __cdecl __get_errno_from_oserr(ulong param_1);
int * __cdecl __errno(void);
ulong * __cdecl ___doserrno(void);
void __cdecl __dosmaperr(ulong param_1);
int __cdecl __heap_init(void);
void __cdecl __heap_term(void);
void __cdecl ___crtCorExitProcess(int param_1);
void __cdecl ___crtExitProcess(int param_1);
void FUN_3b40788c(void);
void FUN_3b407895(void);
void __cdecl __init_pointers(void);
void __cdecl __initterm_e(undefined **param_1,undefined **param_2);
int __cdecl __cinit(int param_1);
void __cdecl _doexit(int param_1,int param_2,int param_3);
void FUN_3b407ab7(void);
void __cdecl __exit(int _Code);
void __cdecl __cexit(void);
void __cdecl __amsg_exit(int param_1);
void * __cdecl __malloc_crt(size_t _Size);
void * __cdecl __calloc_crt(size_t _Count,size_t _Size);
void * __cdecl __realloc_crt(void *_Ptr,size_t _NewSize);
void * __cdecl __recalloc_crt(void *_Ptr,size_t _Count,size_t _Size);
size_t __cdecl __msize(void *_Memory);
void __cdecl __SEH_prolog4(undefined4 param_1,int param_2);
void __SEH_epilog4(void);
undefined4 __cdecl __except_handler4(PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3);
int __cdecl __close_nolock(int _FileHandle);
int __cdecl __close(int _FileHandle);
void FUN_3b407fc7(void);
int __cdecl __fileno(FILE *_File);
void __cdecl __freebuf(FILE *_File);
int __cdecl __flush(FILE *_File);
int __cdecl __fflush_nolock(FILE *_File);
int __cdecl _flsall(int param_1);
void FUN_3b408178(void);
void FUN_3b4081a7(void);
void __cdecl FUN_3b4081b9(undefined4 param_1);
void __cdecl __call_reportfault(int nDbgHookCode,DWORD dwExceptionCode,DWORD dwExceptionFlags);
void __cdecl __invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5);
void __invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5);
void FUN_3b408343(void);
ulong __cdecl strtoxl(localeinfo_struct *param_1,char *param_2,char **param_3,int param_4,int param_5);
long __cdecl _strtol(char *_Str,char **_EndPtr,int _Radix);
int __cdecl __filbuf(FILE *_File);
int __cdecl __ioinit(void);
void __cdecl __ioterm(void);
FILE * __cdecl __openfile(char *_Filename,char *_Mode,int _ShFlag,FILE *_File);
FILE * __cdecl __getstream(void);
void FUN_3b408d24(void);
void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3);
void FUN_3b408e06(int param_1);
void __fastcall @_EH4_CallFilterFunc@8(undefined *param_1);
void __fastcall @_EH4_TransferToHandler@8(undefined *UNRECOVERED_JUMPTABLE);
void __fastcall @_EH4_GlobalUnwind2@8(PVOID param_1,PEXCEPTION_RECORD param_2);
void __fastcall @_EH4_LocalUnwind@16(int param_1,uint param_2,undefined4 param_3,uint *param_4);
undefined (*) [16] __fastcall __VEC_memzero(undefined (*param_1) [16],uint param_2);
int __cdecl CPtoLCID(int param_1);
void __cdecl setSBCS(threadmbcinfostruct *param_1);
void __cdecl setSBUpLow(threadmbcinfostruct *param_1);
pthreadmbcinfo __cdecl ___updatetmbcinfo(void);
void FUN_3b40920a(void);
int __cdecl getSystemCP(int param_1);
void __cdecl __setmbcp_nolock(undefined4 param_1,int param_2);
int __cdecl __setmbcp(int _CodePage);
void FUN_3b4095d9(void);
undefined4 ___initmbctable(void);
void __cdecl ___addlocaleref(LONG *param_1);
LONG * __cdecl ___removelocaleref(LONG *param_1);
void __cdecl ___freetlocinfo(void *param_1);
LONG * __cdecl __updatetlocinfoEx_nolock(LONG **param_1,LONG *param_2);
pthreadlocinfo __cdecl ___updatetlocinfo(void);
void FUN_3b40995d(void);
int __cdecl __tolower_l(int _C,_locale_t _Locale);
int __cdecl __flsbuf(int _Ch,FILE *_File);
void __fastcall _write_char(FILE *param_1);
void __cdecl FUN_3b409c15(undefined4 param_1,int param_2);
void __cdecl FUN_3b409c77(FILE *param_1,byte *param_2,localeinfo_struct *param_3,int **param_4);
int __cdecl __stbuf(FILE *_File);
void __cdecl __ftbuf(int _Flag,FILE *_File);
void FUN_3b40a9e2(void);
int __cdecl __mtinitlocks(void);
void __cdecl __mtdeletelocks(void);
void __cdecl FUN_3b40aa8c(int param_1);
int __cdecl __mtinitlocknum(int _LockNum);
void FUN_3b40ab5c(void);
void __cdecl __lock(int _File);
undefined4 __cdecl ___check_float_string(size_t param_1,void *param_2,undefined4 *param_3);
uint __cdecl __hextodec(byte param_1);
uint __fastcall __inc(undefined4 param_1,FILE *param_2);
uint __thiscall __whiteout(void *this,FILE *param_1);
int __cdecl __input_l(FILE *_File,uchar *param_2,_locale_t _Locale,va_list _ArgList);
int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount);
int __cdecl __setenvp(void);
void __fastcall _parse_cmdline(undefined4 param_1,byte *param_2,byte **param_3,byte *param_4,int *param_5);
int __cdecl __setargv(void);
LPVOID __cdecl ___crtGetEnvironmentStringsA(void);
void __RTC_Initialize(void);
int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr);
int __cdecl ___CppXcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr);
undefined4 performInitialization(void);
void __cdecl ___security_init_cookie(void);
void __cdecl __initp_misc_winsig(undefined4 param_1);
uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3);
void FUN_3b40c337(void);
int __cdecl _raise(int _SigNum);
void FUN_3b40c4ab(void);
int __cdecl ___crtMessageBoxW(LPCWSTR _LpText,LPCWSTR _LpCaption,UINT _UType);
errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src);
errno_t __cdecl _wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount);
size_t __cdecl _wcslen(wchar_t *_Str);
errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src);
int __cdecl __set_error_mode(int _Mode);
void __cdecl __freea(void *_Memory);
void __cdecl __EH_prolog3_catch(int param_1);
int __cdecl _ValidateRead(void *param_1,uint param_2);
void * __cdecl FID_conflict:_memcpy(void *_Dst,void *_Src,size_t _Size);
void __cdecl ___report_gsfailure(void);
void __cdecl __global_unwind2(PVOID param_1);
void __cdecl __local_unwind2(int param_1,uint param_2);
undefined4 __fastcall __NLG_Notify1(undefined4 param_1);
void __NLG_Notify(ulong param_1);
void FUN_3b40ce64(void);
void __cdecl FUN_3b40ce67(undefined4 param_1);
void __initp_misc_cfltcvt_tab(void);
BOOL __cdecl __ValidateImageBase(PBYTE pImageBase);
PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva);
BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget);
LPVOID __cdecl __calloc_impl(uint param_1,uint param_2,undefined4 *param_3);
void * __cdecl _realloc(void *_Memory,size_t _NewSize);
void * __cdecl __recalloc(void *_Memory,size_t _Count,size_t _Size);
int __cdecl __set_osfhnd(int param_1,intptr_t param_2);
int __cdecl __free_osfhnd(int param_1);
intptr_t __cdecl __get_osfhandle(int _FileHandle);
int __cdecl ___lock_fhandle(int _Filehandle);
void FUN_3b40d38f(void);
void __cdecl __unlock_fhandle(int _Filehandle);
int __cdecl __alloc_osfhnd(void);
void FUN_3b40d491(void);
void FUN_3b40d54f(void);
int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount);
int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount);
void FUN_3b40dd21(void);
int __cdecl __commit(int _FileHandle);
void FUN_3b40ddfa(void);
void FUN_3b40de02(void);
int __cdecl __isctype_l(int _C,int _Type,_locale_t _Locale);
longlong __allmul(uint param_1,uint param_2,uint param_3,uint param_4);
undefined8 __aulldvrm(uint param_1,uint param_2,uint param_3,uint param_4);
int __cdecl __read_nolock(int _FileHandle,void *_DstBuf,uint _MaxCharCount);
int __cdecl __read(int _FileHandle,void *_DstBuf,uint _MaxCharCount);
void FUN_3b40e64a(void);
void __cdecl __getbuf(FILE *_File);
int __cdecl FUN_3b40e69b(undefined4 *param_1,LPCSTR param_2,uint param_3,int param_4,byte param_5);
errno_t __cdecl __sopen_helper(char *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure);
void FUN_3b40ee65(void);
errno_t __cdecl __sopen_s(int *_FileHandle,char *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionMode);
int __cdecl __mbsnbicmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale);
int __cdecl __mbsnbicmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount);
int __cdecl __mbsnbcmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale);
int __cdecl __mbsnbcmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount);
int __cdecl __crtLCMapStringA_stat(localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,char *param_6,int param_7,int param_8,int param_9);
int __cdecl ___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError);
int __cdecl __crtGetStringTypeA_stat(localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,int param_6,int param_7,int param_8);
BOOL __cdecl ___crtGetStringTypeA(_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,int _Code_page,BOOL _BError);
void __cdecl ___free_lc_time(void **param_1);
void __cdecl ___free_lconv_num(void **param_1);
void __cdecl ___free_lconv_mon(int param_1);
int __cdecl __isleadbyte_l(int _C,_locale_t _Locale);
int __cdecl _isleadbyte(int _C);
size_t __cdecl _strcspn(char *_Str,char *_Control);
void * __cdecl FID_conflict:_memcpy(void *_Dst,void *_Src,size_t _Size);
int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
char * __cdecl _strpbrk(char *_Str,char *_Control);
longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin);
longlong __cdecl __lseeki64(int _FileHandle,longlong _Offset,int _Origin);
void FUN_3b4100e5(void);
int __cdecl __isatty(int _FileHandle);
bool FUN_3b410145(void);
errno_t __cdecl __wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,_locale_t _Locale);
errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh);
int __cdecl __isdigit_l(int _C,_locale_t _Locale);
int __cdecl _isdigit(int _C);
int __cdecl __isxdigit_l(int _C,_locale_t _Locale);
int __cdecl _isxdigit(int _C);
int __cdecl __isspace_l(int _C,_locale_t _Locale);
int __cdecl _isspace(int _C);
int __cdecl __ungetc_nolock(int _Ch,FILE *_File);
int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale);
int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes);
int __cdecl x_ismbbtype_l(localeinfo_struct *param_1,uint param_2,int param_3,int param_4);
int __cdecl __ismbblead(uint _C);
uint __alloca_probe_16(undefined1 param_1);
uint __alloca_probe_8(undefined1 param_1);
undefined4 * __fastcall __VEC_memcpy(uint param_1);
wint_t __cdecl __putwch_nolock(wchar_t _WCh);
void __alloca_probe(void);
int __cdecl __chsize_nolock(int _FileHandle,longlong _Size);
long __cdecl __lseek_nolock(int _FileHandle,long _Offset,int _Origin);
int __cdecl __setmode_nolock(int _FileHandle,int _Mode);
errno_t __cdecl __get_fmode(int *_PMode);
void __cdecl ___initconout(void);
void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue);

