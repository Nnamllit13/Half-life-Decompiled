typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined7;
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

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef int BOOL;

typedef char CHAR;

typedef CHAR * LPSTR;

typedef BOOL (* LOCALE_ENUMPROCA)(LPSTR);

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

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

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef ushort WORD;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef long LONG;

typedef wchar_t WCHAR;

typedef struct _SYSTEMTIME SYSTEMTIME;

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef void * LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef BYTE * LPBYTE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
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

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _TIME_ZONE_INFORMATION * LPTIME_ZONE_INFORMATION;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

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

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

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

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

#define __STDC_VERSION__ 199900

#define WINAPI_PARTITION_GAMES 1

#define WINAPI_PARTITION_SYSTEM 1

#define BSD 199103

#define _WIN32_WINNT 2560

#define WINAPI_PARTITION_APP 1

#define WINVER 2304

#define _INTEGRAL_MAX_BITS 32

#define _MSC_VER 1200

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

typedef uint size_t;

typedef WCHAR * LPWSTR;

typedef WCHAR * PCNZWCH;

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef CHAR * LPCH;

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef struct _OSVERSIONINFOA * LPOSVERSIONINFOA;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef CHAR * PCNZCH;

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
    byte e_program[176]; // Actual DOS program
};

typedef ULONG_PTR SIZE_T;

typedef uint UINT_PTR;

typedef long LONG_PTR;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef UINT_PTR WPARAM;

typedef DWORD * LPDWORD;

typedef LONG_PTR LPARAM;

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

typedef struct _FILETIME * LPFILETIME;

typedef int (* FARPROC)(void);

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef WORD * LPWORD;

typedef BOOL * LPBOOL;

typedef void * LPCVOID;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
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

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef struct WSAData WSAData, *PWSAData;

typedef struct WSAData WSADATA;

struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    ushort iMaxSockets;
    ushort iMaxUdpDg;
    char * lpVendorInfo;
};

typedef WSADATA * LPWSADATA;




void FUN_0140100a(void);
void FUN_01401014(void);
void __fastcall FUN_0140102a(undefined4 *param_1);
undefined4 * __thiscall FUN_01401037(void *this,byte param_1);
void __fastcall FUN_01401053(undefined4 *param_1);
void FUN_01401063(uint *param_1);
uint * __cdecl FUN_0140115e(uint *param_1);
void __thiscall FUN_0140118a(void *this,char *param_1);
void __thiscall FUN_0140124d(void *this,uint *param_1,uint *param_2);
void __thiscall FUN_01401325(void *this,undefined4 param_1);
void __thiscall FUN_01401344(void *this,undefined4 param_1,undefined4 param_2);
uint * __thiscall FUN_0140137a(void *this,char *param_1,undefined4 *param_2);
undefined4 __cdecl CreateInterface(char *param_1,undefined4 *param_2);
void __cdecl FUN_01401461(LPCSTR param_1);
void __cdecl FUN_014014a2(HMODULE param_1);
FARPROC __cdecl FUN_014014b4(HMODULE param_1);
undefined * FUN_014014ce(void);
undefined * FUN_014014fb(void);
void __cdecl FUN_01401578(char **param_1);
bool FUN_01401632(void);
bool __cdecl FUN_0140169e(LPSTR param_1,DWORD param_2);
int __cdecl FUN_014016bc(uint *param_1);
undefined4 FUN_01401746(undefined4 win_modul,undefined4 param_2,HKEY param_3);
uint __cdecl FUN_01401d22(int param_1,undefined4 param_2,undefined4 param_3,int param_4);
void __cdecl FUN_01401dce(int param_1);
void FUN_01401e5c(void);
void FUN_01401e66(void);
void __fastcall FUN_01401e7c(undefined4 *param_1);
undefined4 * __thiscall FUN_01401e8d(void *this,byte param_1);
void __fastcall FUN_01401ea9(undefined4 *param_1);
int __thiscall FUN_01401eb0(void *this,LPCSTR param_1,int param_2);
undefined * __thiscall FUN_01401f16(void *this,LPCSTR param_1,undefined *param_2);
void __thiscall FUN_01401f62(void *this,LPCSTR param_1,BYTE *param_2);
void __fastcall FUN_01401f90(int param_1);
char * FUN_01401fee(void);
bool __cdecl FUN_01402008(byte *param_1);
uint __cdecl FUN_01402023(HKEY param_1,byte *param_2,byte *param_3);
void __cdecl FUN_01402088(HKEY param_1);
int * __cdecl FUN_014023a0(int *param_1);
int __cdecl FUN_0140241e(int *param_1);
void __fastcall FUN_0140245f(undefined4 *param_1);
undefined4 * __thiscall FUN_01402488(void *this,byte param_1);
void __cdecl FUN_0140250e(undefined *param_1);
uint __thiscall FUN_014025ec(void *this,int param_1);
undefined4 __cdecl FUN_0140277d(FILE *param_1);
undefined4 __cdecl __fclose_lk(FILE *param_1);
uint __cdecl FUN_014027fa(byte **param_1);
int __cdecl FUN_01402836(byte *param_1);
undefined4 * __cdecl FUN_01402877(LPCSTR param_1,char *param_2,uint param_3);
void __cdecl FUN_014028a8(LPCSTR param_1,char *param_2);
void FUN_014028c0(undefined1 param_1);
uint * __cdecl FUN_014028f0(uint *param_1,uint *param_2);
uint * __cdecl FUN_01402900(uint *param_1,uint *param_2);
void * __cdecl dynamische_Speicherallokation(uint Memory_size);
size_t __cdecl _strlen(char *_Str);
void * __cdecl Initialize_Memory(void *_Dst,int _Val,size_t _Size);
undefined4 * __cdecl FUN_01402ad0(undefined4 *param_1,undefined4 *param_2,uint param_3);
uint * __cdecl FUN_01402e10(uint *param_1,char *param_2);
int __cdecl FUN_01402e90(char *param_1,int param_2,byte *param_3);
int __cdecl _strcmp(char *_Str1,char *_Str2);
char * __cdecl _strrchr(char *_Str,int _Ch);
HANDLE __cdecl FUN_01402fa7(LPCSTR param_1,uint *param_2);
undefined4 __cdecl FUN_01403074(HANDLE param_1,uint *param_2);
undefined4 __cdecl FUN_0140313c(HANDLE param_1);
int __cdecl ConvertFileTimeToTimeT(FILETIME *pFileTime);
uint * __cdecl FUN_014031d0(uint *param_1,char param_2);
int __cdecl FUN_0140328c(char *param_1,byte *param_2);
undefined4 __cdecl FUN_014032fd(uint param_1);
undefined4 __cdecl FUN_014033b0(undefined4 param_1);
uint __cdecl FUN_014033f8(int param_1);
void __cdecl FUN_01403423(uint *param_1,int param_2);
int * __cdecl Allocate_Memory(uint *pRequestedSize);
undefined4 * Allocate_Memory_Block(void);
int __cdecl Allocate_Memory_Block(int iMemoryBlockIndex);
undefined4 __cdecl FUN_01403c01(uint *param_1,int param_2,int param_3);
undefined4 FUN_01403fc8(void);
undefined ** FUN_01404319(void);
void __cdecl FUN_0140445d(undefined **param_1);
void __cdecl FUN_014044b3(int param_1);
int __cdecl FUN_01404575(undefined *param_1,int **param_2,uint *param_3);
void __cdecl FUN_014045cc(int param_1,int param_2,byte *param_3);
int * __cdecl Memory_manager(int *param_1);
int __cdecl FUN_01404819(int **param_1,int *param_2,int *param_3);
undefined4 __cdecl FUN_0140493d(int param_1,int **param_2,int **param_3,uint param_4);
int FUN_014049e6(void);
char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count);
void __cdecl FUN_01404c4e(undefined *param_1);
void FUN_01404cb8(void);
void FUN_01404d10(void);
void * __cdecl _malloc(size_t mem_Size);
void * __cdecl malloc_mem(size_t mem_Size,int error_Flag);
void __cdecl Speicherallokation(uint *mem_size);
void endCritical_9(void);
void endCritical_9(void);
uint __cdecl FUN_01404e71(byte param_1,byte *param_2);
undefined4 __cdecl FUN_01404f29(byte *param_1,int *param_2);
undefined4 __cdecl FUN_014051e4(char *param_1);
void __cdecl FUN_01405254(int param_1,uint *param_2,uint **param_3);
undefined4 __cdecl FUN_0140526b(LPCSTR param_1);
void entry(void);
void __cdecl __amsg_exit(int exitCode);
void __cdecl FUN_0140541e(DWORD input);
void FUN_01405442(void);
void __cdecl __exit2(UINT exit_code);
void __cdecl __exit1(int exit_Code);
void __cdecl exit_handeler(UINT input_exitcode,int Skipe,int exit);
void execude_0xd(void);
void endCritical_0xd(void);
void __cdecl callValidFunctionPointers(undefined **param_1,undefined **param_2);
int ** __cdecl FUN_01405580(int **param_1,uint *param_2);
void FUN_0140570b(void);
void FUN_01405859(void);
SIZE_T __cdecl FUN_014058af(undefined *param_1);
void FUN_01405919(void);
void FUN_01405994(void);
void Initialize_Thread_Local_Storage(void);
void __cdecl critical_code_area_executor(int mem_adresse);
void __cdecl endCriticalFromID(int param_1);
uint __thiscall FUN_01405ac0(void *this,int param_1,uint param_2);
void __cdecl FUN_01405bf1(uint param_1);
void __cdecl FUN_01405c20(int param_1,int param_2);
void __cdecl FUN_01405c43(uint param_1);
void __cdecl FUN_01405c72(int param_1,int param_2);
undefined4 __cdecl FUN_01405c95(uint param_1);
undefined4 __cdecl FUN_01405cf2(uint param_1);
void __cdecl __freebuf(FILE *_File);
int __cdecl FUN_01405da0(int *param_1);
int __cdecl FUN_01405dcf(int *param_1);
undefined4 __cdecl FUN_01405dfd(int *param_1);
int __cdecl FUN_01405e62(int param_1);
uint __cdecl FUN_01405f06(byte **param_1);
undefined4 __cdecl FUN_01405fe2(void **param_1);
void __cdecl FUN_0140606f(int param_1,int *param_2);
int __cdecl FUN_01406099(char **param_1,byte *param_2,undefined4 *param_3);
void __cdecl FUN_014067da(uint param_1,char **param_2,int *param_3);
void __cdecl FUN_0140680f(uint param_1,int param_2,char **param_3,int *param_4);
void __cdecl FUN_01406840(char *param_1,int param_2,char **param_3,int *param_4);
undefined4 __cdecl FUN_01406878(int *param_1);
undefined8 __cdecl FUN_01406885(int *param_1);
undefined4 __cdecl FUN_01406895(int *param_1);
undefined4 * __cdecl FUN_014068a3(LPCSTR param_1,char *param_2,uint param_3,undefined4 *param_4);
undefined4 * FUN_01406a13(void);
uint __cdecl FUN_01406adb(uint param_1,char **param_2);
void __cdecl FUN_01406bf3(uint param_1);
DWORD * FUN_01406c66(void);
DWORD * FUN_01406c6f(void);
int __cdecl ConvertSystemTimeToTimeT(int iYear,int iMonth,int iDay,int iHour,int iMinute,int iSecond,int iDST);
void __cdecl FUN_01406d3a(undefined4 *param_1);
int FUN_01406d67(void);
undefined4 __cdecl FUN_01406eaf(int param_1);
undefined4 * __cdecl FUN_01406fc0(undefined4 *param_1,undefined4 *param_2,uint param_3);
void __cdecl __global_unwind2(PVOID param_1);
void __cdecl __local_unwind2(int param_1,int param_2);
void FUN_014073ce(void);
void FUN_014074ad(int param_1);
undefined4 __cdecl CheckMemoryAllocation(int mem_size);
uint __thiscall FUN_0140750d(void *this,byte *param_1,byte *param_2);
byte * __cdecl FUN_014076a2(byte *param_1,uint param_2);
uint * __cdecl FUN_01407714(uint *param_1,LPCSTR param_2,size_t param_3);
int FUN_014077b9(void);
undefined4 __cdecl FUN_014077fc(uint param_1);
uint __cdecl FUN_0140786f(uint param_1);
byte * __cdecl FUN_014078ea(byte *param_1,byte *param_2);
char * __cdecl FUN_0140797f(int param_1,uint *param_2,uint **param_3,uint **param_4);
char * __cdecl FUN_01407ac8(int param_1,LPCSTR param_2,uint **param_3,uint **param_4);
uint __cdecl FUN_01407b19(uint param_1);
LONG __cdecl FUN_01407b94(int param_1,_EXCEPTION_POINTERS *param_2);
int * __cdecl FUN_01407cd2(int param_1,int *param_2);
byte * FUN_01407d0c(void);
void FUN_01407d64(void);
void FUN_01407e1d(void);
void __cdecl FUN_01407eb6(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5);
undefined4 * FUN_0140806a(void);
void FUN_0140819c(void);
void FUN_01408358(void);
undefined4 TLS-Thread_Local_Storage(void);
void __cdecl Mem_magic(int mem_input);
DWORD * FUN_01408431(void);
void performExitRoutine(void);
void __cdecl executeExitProcedure(DWORD input_param);
BOOL __cdecl FUN_01408701(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,int param_7);
int * __cdecl Allocate_Memory(int iNumElements,int iElementSize);
void endCritical_9(void);
void endCritical_9(void);
uint FUN_01408a08(void);
undefined4 __cdecl FUN_01408b2b(uint param_1,HANDLE param_2);
undefined4 __cdecl FUN_01408ba7(uint param_1);
undefined4 __cdecl FUN_01408c26(uint param_1);
uint __cdecl FUN_01408c68(HANDLE param_1,uint param_2);
void __cdecl FUN_01408d0f(uint param_1);
void __cdecl FUN_01408d6e(uint param_1);
DWORD __cdecl FUN_01408d90(uint param_1);
int __cdecl FUN_01408e23(uint param_1,char *param_2,uint param_3);
int __cdecl FUN_01408e88(DWORD param_1,char *param_2,uint param_3);
int __cdecl FUN_01409013(uint param_1,char *param_2,char *param_3);
int __cdecl FUN_01409078(uint param_1,char *param_2,char *param_3);
void __cdecl FUN_01409251(undefined4 *param_1);
byte __cdecl FUN_01409295(uint param_1);
LPSTR __cdecl FUN_014092be(LPSTR param_1,WCHAR param_2);
LPSTR __cdecl FUN_01409317(LPSTR param_1,WCHAR param_2);
undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4);
undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4);
uint __cdecl FUN_0140947c(LPCSTR param_1,uint param_2,uint param_3,uint param_4);
DWORD __cdecl FUN_0140974b(uint param_1,LONG param_2,DWORD param_3);
DWORD __cdecl FUN_014097b0(uint param_1,LONG param_2,DWORD param_3);
void InitializeCriticalSection(void);
void InitializeCriticalSectionAndSpinCount(void);
bool __cdecl FUN_01409aee(int *param_1);
bool __cdecl FUN_01409b0f(int *param_1);
void __cdecl FUN_01409cbb(int param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,int param_7,int param_8,int param_9,int param_10,int param_11);
void __thiscall FUN_01409dfb(void *this,byte *param_1,byte **param_2,undefined *param_3);
undefined * __thiscall FUN_01409e12(void *this,byte *param_1,byte **param_2,undefined *param_3,uint param_4);
int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
undefined4 __cdecl FUN_0140a068(int param_1);
int __cdecl FUN_0140a215(int param_1);
undefined4 __cdecl FUN_0140a25f(int param_1);
void FUN_0140a292(void);
void FUN_0140a2bb(void);
void FUN_0140a450(void);
int __cdecl FUN_0140a46c(LCID param_1,uint param_2,char *param_3,int param_4,LPWSTR param_5,int param_6,UINT param_7,int param_8);
int __cdecl FUN_0140a690(char *param_1,int param_2);
uint __thiscall FUN_0140a6c0(void *this,byte *param_1,byte *param_2);
uint * __cdecl FUN_0140a790(uint *param_1,size_t param_2);
uint * __cdecl FUN_0140a7e0(uint param_1,uint *param_2,size_t param_3);
undefined4 __cdecl FUN_0140a8b5(uint param_1);
uint __cdecl FUN_0140a8f4(uint param_1);
uint __thiscall FUN_0140a963(void *this,uint param_1);
byte * __cdecl FUN_0140aa30(byte *param_1,byte *param_2);
undefined4 __cdecl FUN_0140aa6a(LPCSTR param_1,byte param_2);
uint * __cdecl FUN_0140aab0(uint *param_1,uint param_2);
char * __cdecl FUN_0140ab47(int param_1,LPCSTR param_2,char *param_3,LPVOID param_4);
undefined4 __cdecl FUN_0140ad30(uint **param_1,uint **param_2,uint **param_3,uint **param_4);
void __cdecl FUN_0140afca(byte param_1);
undefined4 __cdecl FUN_0140b013(byte param_1,uint param_2,byte param_3);
int __cdecl Window_MessageBox_Manager(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void FUN_0140b0cd(void);
uint * __cdecl FUN_0140b0d6(int param_1,uint *param_2);
undefined4 __cdecl FUN_0140b31c(int param_1,uint *param_2);
uint * FUN_0140b437(void);
uint * __cdecl FUN_0140b4f0(uint *param_1,uint *param_2,undefined4 *param_3,undefined4 *param_4);
void __cdecl FUN_0140b60b(uint *param_1,int param_2);
undefined4 __cdecl FUN_0140b630(char *param_1,byte *param_2);
void __cdecl FUN_0140b6fc(uint *param_1,uint *param_2);
int __cdecl FUN_0140b74f(uint param_1,int param_2);
int __cdecl FUN_0140b7a8(uint param_1,int param_2);
int __thiscall FUN_0140b8cd(void *this,byte *param_1);
uchar * __cdecl FUN_0140ba3e(uchar *param_1);
uint __thiscall FUN_0140bb32(void *this,uint param_1);
uint __cdecl FUN_0140bc8e(char **param_1);
void __cdecl FUN_0140bfdc(undefined4 *param_1);
void __cdecl FUN_0140c341(char *param_1);
uint __cdecl FUN_0140c443(int param_1);
void __cdecl FUN_0140c565(char *param_1);
void __cdecl FUN_0140c59c(int param_1);
undefined4 FUN_0140c5ea(void);
int __cdecl FUN_0140c840(byte *param_1,byte *param_2);
undefined4 __thiscall FUN_0140c87e(void *this,char *param_1,undefined2 *param_2,int param_3);
void __thiscall FUN_0140c9fb(void *this,int param_1,int param_2,byte **param_3);
void FUN_0140ca53(void);
uint FUN_0140cada(char *param_1);
void FUN_0140ccde(void);
uint FUN_0140cd34(char *param_1);
void FUN_0140cdf1(void);
uint FUN_0140ce28(char *param_1);
void FUN_0140ceae(void);
void __cdecl FUN_0140cec8(byte *param_1);
undefined4 __cdecl FUN_0140cf2e(short param_1);
undefined4 __cdecl FUN_0140cf4d(int param_1,int param_2);
undefined4 FUN_0140cfaf(void);
int FUN_0140cfe5(uint param_1,LCTYPE param_2,char *param_3,int param_4);
int __cdecl FUN_0140d0cb(char *param_1);
int __cdecl FUN_0140d104(char *param_1);
int __cdecl FUN_0140d125(uint param_1,int param_2);
int __cdecl FUN_0140d17e(uint param_1,int param_2);
int __cdecl __mbsnbicoll(uchar *_Str1,uchar *_Str2,size_t _MaxCount);
undefined4 FUN_0140d253(void);
undefined * FUN_0140d2c1(void);
undefined * FUN_0140d350(void);
uint ** FUN_0140d3e5(void);
int __cdecl FUN_0140d632(byte *param_1,uint param_2,byte *param_3,int *param_4,undefined *param_5);
void __cdecl FUN_0140d72c(char param_1,int *param_2,byte **param_3,uint *param_4,int param_5);
void __cdecl FUN_0140db1b(char *param_1,char **param_2,int *param_3);
void __cdecl FUN_0140db42(int param_1,uint param_2,char **param_3,uint *param_4);
void __cdecl FUN_0140dbb1(int param_1,char **param_2,uint *param_3);
void __cdecl FUN_0140dbfa(byte *param_1,int param_2,byte **param_3,uint *param_4,int param_5);
undefined4 __cdecl FUN_0140dec9(int param_1,LCID param_2,LCTYPE param_3,char **param_4);
BOOL __cdecl FUN_0140e007(DWORD param_1,LPCWSTR param_2,int param_3,undefined4 *param_4,UINT param_5,LCID param_6);
char * __cdecl FUN_0140e1cc(uint param_1,char *param_2,uint param_3);
void __cdecl FUN_0140e1f9(uint param_1,char *param_2,uint param_3,int param_4);
char * __cdecl FUN_0140e255(uint param_1,char *param_2,uint param_3);
char * __cdecl FUN_0140e29a(int param_1,int param_2,char *param_3,uint param_4);
void FUN_0140e2cb(int param_1,int param_2,char *param_3,uint param_4,int param_5);
char * __cdecl FUN_0140e351(int param_1,int param_2,char *param_3,uint param_4);
void * __cdecl FUN_0140e370(byte *param_1,char *param_2,void *param_3);
int __cdecl FUN_0140e471(LCID param_1,DWORD param_2,byte *param_3,int param_4,byte *param_5,int param_6,UINT param_7);
int __cdecl FUN_0140e6ee(char *param_1,int param_2);
undefined4 __cdecl FUN_0140e719(uint *param_1,int param_2);
int __cdecl FUN_0140e8a0(uchar *param_1,size_t param_2);
uint ** __cdecl FUN_0140e8f8(uint **param_1);
int __cdecl FUN_0140e95f(LCID param_1,LCTYPE param_2,LPWSTR param_3,int param_4,UINT param_5);
int __cdecl FUN_0140ea72(LCID param_1,LCTYPE param_2,LPSTR param_3,int param_4,UINT param_5);
uint * __cdecl FUN_0140eb90(uint *param_1);
void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue);
undefined4 __cdecl FUN_0140ed8e(LPCSTR param_1);
void __cdecl FUN_0140edb8(LPCSTR param_1);

