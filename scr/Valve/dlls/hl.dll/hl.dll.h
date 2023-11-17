typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned int    uint3;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION * LPTIME_ZONE_INFORMATION;

typedef long LONG;

typedef wchar_t WCHAR;

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

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

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

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

typedef BOOL (* PHANDLER_ROUTINE)(DWORD);

typedef uint size_t;

typedef int errno_t;

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

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef int (* FARPROC)(void);

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

typedef struct CBaseEntity CBaseEntity, *PCBaseEntity;

struct CBaseEntity { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct CTestHull CTestHull, *PCTestHull;

struct CTestHull { // PlaceHolder Structure
};

typedef struct CBaseDoor CBaseDoor, *PCBaseDoor;

struct CBaseDoor { // PlaceHolder Structure
};

typedef struct CGunTarget CGunTarget, *PCGunTarget;

struct CGunTarget { // PlaceHolder Structure
};

typedef struct CIchthyosaur CIchthyosaur, *PCIchthyosaur;

struct CIchthyosaur { // PlaceHolder Structure
};

typedef struct CHeadCrab CHeadCrab, *PCHeadCrab;

struct CHeadCrab { // PlaceHolder Structure
};

typedef struct CNihilanth CNihilanth, *PCNihilanth;

struct CNihilanth { // PlaceHolder Structure
};

typedef struct CTalkMonster CTalkMonster, *PCTalkMonster;

struct CTalkMonster { // PlaceHolder Structure
};

typedef struct CControllerZapBall CControllerZapBall, *PCControllerZapBall;

struct CControllerZapBall { // PlaceHolder Structure
};

typedef struct CWallHealth CWallHealth, *PCWallHealth;

struct CWallHealth { // PlaceHolder Structure
};

typedef struct CTentacle CTentacle, *PCTentacle;

struct CTentacle { // PlaceHolder Structure
};

typedef struct CControllerHeadBall CControllerHeadBall, *PCControllerHeadBall;

struct CControllerHeadBall { // PlaceHolder Structure
};

typedef struct CItemSoda CItemSoda, *PCItemSoda;

struct CItemSoda { // PlaceHolder Structure
};

typedef struct CGibShooter CGibShooter, *PCGibShooter;

struct CGibShooter { // PlaceHolder Structure
};

typedef struct CItem CItem, *PCItem;

struct CItem { // PlaceHolder Structure
};

typedef struct CEnvExplosion CEnvExplosion, *PCEnvExplosion;

struct CEnvExplosion { // PlaceHolder Structure
};

typedef struct CFuncTrain CFuncTrain, *PCFuncTrain;

struct CFuncTrain { // PlaceHolder Structure
};

typedef struct CSqueakGrenade CSqueakGrenade, *PCSqueakGrenade;

struct CSqueakGrenade { // PlaceHolder Structure
};

typedef struct CFrictionModifier CFrictionModifier, *PCFrictionModifier;

struct CFrictionModifier { // PlaceHolder Structure
};

typedef struct CPendulum CPendulum, *PCPendulum;

struct CPendulum { // PlaceHolder Structure
};

typedef struct CTriggerCamera CTriggerCamera, *PCTriggerCamera;

struct CTriggerCamera { // PlaceHolder Structure
};

typedef struct CTripmineGrenade CTripmineGrenade, *PCTripmineGrenade;

struct CTripmineGrenade { // PlaceHolder Structure
};

typedef struct CNodeViewer CNodeViewer, *PCNodeViewer;

struct CNodeViewer { // PlaceHolder Structure
};

typedef struct CMortar CMortar, *PCMortar;

struct CMortar { // PlaceHolder Structure
};

typedef struct CTriggerSave CTriggerSave, *PCTriggerSave;

struct CTriggerSave { // PlaceHolder Structure
};

typedef struct CFuncMortarField CFuncMortarField, *PCFuncMortarField;

struct CFuncMortarField { // PlaceHolder Structure
};

typedef struct CBreakable CBreakable, *PCBreakable;

struct CBreakable { // PlaceHolder Structure
};

typedef struct CChangeLevel CChangeLevel, *PCChangeLevel;

struct CChangeLevel { // PlaceHolder Structure
};

typedef struct CBaseMonster CBaseMonster, *PCBaseMonster;

struct CBaseMonster { // PlaceHolder Structure
};

typedef struct CSquidSpit CSquidSpit, *PCSquidSpit;

struct CSquidSpit { // PlaceHolder Structure
};

typedef struct CBarnacle CBarnacle, *PCBarnacle;

struct CBarnacle { // PlaceHolder Structure
};

typedef struct CMultiSource CMultiSource, *PCMultiSource;

struct CMultiSource { // PlaceHolder Structure
};

typedef struct CLightning CLightning, *PCLightning;

struct CLightning { // PlaceHolder Structure
};

typedef struct CSpeaker CSpeaker, *PCSpeaker;

struct CSpeaker { // PlaceHolder Structure
};

typedef struct CCrowbar CCrowbar, *PCCrowbar;

struct CCrowbar { // PlaceHolder Structure
};

typedef struct CNihilanthHVR CNihilanthHVR, *PCNihilanthHVR;

struct CNihilanthHVR { // PlaceHolder Structure
};

typedef struct CSatchelCharge CSatchelCharge, *PCSatchelCharge;

struct CSatchelCharge { // PlaceHolder Structure
};

typedef struct CBeam CBeam, *PCBeam;

struct CBeam { // PlaceHolder Structure
};

typedef struct CLeech CLeech, *PCLeech;

struct CLeech { // PlaceHolder Structure
};

typedef struct CMomentaryDoor CMomentaryDoor, *PCMomentaryDoor;

struct CMomentaryDoor { // PlaceHolder Structure
};

typedef struct CGib CGib, *PCGib;

struct CGib { // PlaceHolder Structure
};

typedef struct CLaserSpot CLaserSpot, *PCLaserSpot;

struct CLaserSpot { // PlaceHolder Structure
};

typedef struct CDecal CDecal, *PCDecal;

struct CDecal { // PlaceHolder Structure
};

typedef struct CBasePlayerItem CBasePlayerItem, *PCBasePlayerItem;

struct CBasePlayerItem { // PlaceHolder Structure
};

typedef struct CMonsterMaker CMonsterMaker, *PCMonsterMaker;

struct CMonsterMaker { // PlaceHolder Structure
};

typedef struct CBaseToggle CBaseToggle, *PCBaseToggle;

struct CBaseToggle { // PlaceHolder Structure
};

typedef struct CAmbientGeneric CAmbientGeneric, *PCAmbientGeneric;

struct CAmbientGeneric { // PlaceHolder Structure
};

typedef struct CFuncPlat CFuncPlat, *PCFuncPlat;

struct CFuncPlat { // PlaceHolder Structure
};

typedef struct CFuncTrackChange CFuncTrackChange, *PCFuncTrackChange;

struct CFuncTrackChange { // PlaceHolder Structure
};

typedef struct CBaseTurret CBaseTurret, *PCBaseTurret;

struct CBaseTurret { // PlaceHolder Structure
};

typedef struct CMomentaryRotButton CMomentaryRotButton, *PCMomentaryRotButton;

struct CMomentaryRotButton { // PlaceHolder Structure
};

typedef struct CAirtank CAirtank, *PCAirtank;

struct CAirtank { // PlaceHolder Structure
};

typedef struct CBaseTrigger CBaseTrigger, *PCBaseTrigger;

struct CBaseTrigger { // PlaceHolder Structure
};

typedef struct CMultiManager CMultiManager, *PCMultiManager;

struct CMultiManager { // PlaceHolder Structure
};

typedef struct CRevertSaved CRevertSaved, *PCRevertSaved;

struct CRevertSaved { // PlaceHolder Structure
};

typedef struct CSittingScientist CSittingScientist, *PCSittingScientist;

struct CSittingScientist { // PlaceHolder Structure
};

typedef struct CFuncTrackTrain CFuncTrackTrain, *PCFuncTrackTrain;

struct CFuncTrackTrain { // PlaceHolder Structure
};

typedef struct CRpgRocket CRpgRocket, *PCRpgRocket;

struct CRpgRocket { // PlaceHolder Structure
};

typedef enum USE_TYPE {
} USE_TYPE;

typedef struct CCineMonster CCineMonster, *PCCineMonster;

struct CCineMonster { // PlaceHolder Structure
};

typedef struct CTestEffect CTestEffect, *PCTestEffect;

struct CTestEffect { // PlaceHolder Structure
};

typedef struct CGrenade CGrenade, *PCGrenade;

struct CGrenade { // PlaceHolder Structure
};

typedef struct COsprey COsprey, *PCOsprey;

struct COsprey { // PlaceHolder Structure
};

typedef struct CSentry CSentry, *PCSentry;

struct CSentry { // PlaceHolder Structure
};

typedef struct CRoach CRoach, *PCRoach;

struct CRoach { // PlaceHolder Structure
};

typedef struct CSprite CSprite, *PCSprite;

struct CSprite { // PlaceHolder Structure
};

typedef struct CBubbling CBubbling, *PCBubbling;

struct CBubbling { // PlaceHolder Structure
};

typedef struct CLegacyCineMonster CLegacyCineMonster, *PCLegacyCineMonster;

struct CLegacyCineMonster { // PlaceHolder Structure
};

typedef struct CCrossbowBolt CCrossbowBolt, *PCCrossbowBolt;

struct CCrossbowBolt { // PlaceHolder Structure
};

typedef struct CTriggerGravity CTriggerGravity, *PCTriggerGravity;

struct CTriggerGravity { // PlaceHolder Structure
};

typedef struct CFlockingFlyer CFlockingFlyer, *PCFlockingFlyer;

struct CFlockingFlyer { // PlaceHolder Structure
};

typedef struct CRecharge CRecharge, *PCRecharge;

struct CRecharge { // PlaceHolder Structure
};

typedef struct CApacheHVR CApacheHVR, *PCApacheHVR;

struct CApacheHVR { // PlaceHolder Structure
};

typedef struct CCineBlood CCineBlood, *PCCineBlood;

struct CCineBlood { // PlaceHolder Structure
};

typedef struct CFuncRotating CFuncRotating, *PCFuncRotating;

struct CFuncRotating { // PlaceHolder Structure
};

typedef struct CFuncTrainControls CFuncTrainControls, *PCFuncTrainControls;

struct CFuncTrainControls { // PlaceHolder Structure
};

typedef struct CBaseDelay CBaseDelay, *PCBaseDelay;

struct CBaseDelay { // PlaceHolder Structure
};

typedef struct CTriggerEndSection CTriggerEndSection, *PCTriggerEndSection;

struct CTriggerEndSection { // PlaceHolder Structure
};

typedef struct CBMortar CBMortar, *PCBMortar;

struct CBMortar { // PlaceHolder Structure
};

typedef struct CScriptedSentence CScriptedSentence, *PCScriptedSentence;

struct CScriptedSentence { // PlaceHolder Structure
};

typedef struct CHGruntRepel CHGruntRepel, *PCHGruntRepel;

struct CHGruntRepel { // PlaceHolder Structure
};

typedef struct CBasePlayerAmmo CBasePlayerAmmo, *PCBasePlayerAmmo;

struct CBasePlayerAmmo { // PlaceHolder Structure
};

typedef struct CHornet CHornet, *PCHornet;

struct CHornet { // PlaceHolder Structure
};

typedef struct CTriggerHurt CTriggerHurt, *PCTriggerHurt;

struct CTriggerHurt { // PlaceHolder Structure
};

typedef struct CBasePlayer CBasePlayer, *PCBasePlayer;

struct CBasePlayer { // PlaceHolder Structure
};

typedef struct CApache CApache, *PCApache;

struct CApache { // PlaceHolder Structure
};

typedef struct CWeaponBox CWeaponBox, *PCWeaponBox;

struct CWeaponBox { // PlaceHolder Structure
};

typedef struct CLaser CLaser, *PCLaser;

struct CLaser { // PlaceHolder Structure
};

typedef struct CEnvSpark CEnvSpark, *PCEnvSpark;

struct CEnvSpark { // PlaceHolder Structure
};

typedef struct CBaseButton CBaseButton, *PCBaseButton;

struct CBaseButton { // PlaceHolder Structure
};




void __cdecl monster_flyer(int param_1);
void __cdecl monster_flyer_flock(int param_1);
void __thiscall FUN_10001160(void *this,int param_1);
void __fastcall FUN_100011e0(int *param_1);
void __fastcall FUN_10001260(int param_1);
void __fastcall FUN_10001460(int *param_1);
void __fastcall FUN_100014c0(int param_1);
void __thiscall CFlockingFlyer::FallHack(CFlockingFlyer *this);
void __fastcall FUN_10001710(int param_1);
void __fastcall FUN_100017e0(void *param_1);
void __thiscall CFlockingFlyer::IdleThink(CFlockingFlyer *this);
void __thiscall CFlockingFlyer::Start(CFlockingFlyer *this);
void __thiscall CFlockingFlyer::FormFlock(CFlockingFlyer *this);
void __fastcall FUN_10001a30(int param_1);
void __thiscall FUN_10001c70(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3);
void __fastcall FUN_10001c90(int param_1);
bool __fastcall FUN_10001db0(int param_1);
void __thiscall FUN_10002160(void *this,float *param_1,float *param_2);
void __thiscall FUN_10002190(void *this,float *param_1,float param_2);
void __thiscall CFlockingFlyer::FlockLeaderThink(CFlockingFlyer *this);
void __thiscall CFlockingFlyer::FlockFollowerThink(CFlockingFlyer *this);
void __fastcall FUN_100029a0(int param_1);
void __thiscall FUN_100029d0(void *this,int param_1);
void __thiscall FUN_100029f0(void *this,int param_1);
int __fastcall FUN_10002b10(int param_1);
undefined4 __fastcall FUN_10002b30(int *param_1);
void __fastcall FUN_10002bd0(int param_1);
void __thiscall CBaseEntity::SUB_CallUseToggle(CBaseEntity *this);
void __fastcall FUN_10002c90(undefined4 *param_1);
void FUN_10002d60(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4);
void __thiscall CBaseMonster::CallMonsterThink(CBaseMonster *this);
void __fastcall FUN_10002f50(int *param_1);
void __cdecl monster_alien_grunt(int param_1);
void __fastcall FUN_100034a0(int param_1);
undefined4 __fastcall FUN_100034e0(int param_1);
void __fastcall FUN_10003530(int param_1);
void __fastcall FUN_100035e0(int param_1);
void __fastcall FUN_10003620(int param_1);
void __fastcall FUN_10003660(int param_1);
void __fastcall FUN_100036a0(int param_1);
void __thiscall FUN_10003e00(void *this,undefined4 *param_1);
void __fastcall FUN_100046a0(int *param_1);
undefined ** __thiscall FUN_10004790(void *this,int param_1);
void __cdecl item_airtank(int param_1);
void __fastcall FUN_10004920(int *param_1);
void __thiscall FUN_10004a30(void *this,int param_1);
void __thiscall CAirtank::TankThink(CAirtank *this);
void __thiscall CAirtank::TankTouch(CAirtank *this,CBaseEntity *param_1);
void __thiscall FUN_10004b60(void *this,void *param_1);
void __thiscall FUN_10004b90(void *this,void *param_1);
float10 __thiscall FUN_10004bc0(void *this,float param_1);
void __thiscall FUN_10004cf0(void *this,int param_1);
void __thiscall FUN_10004d20(void *this,int param_1);
void __thiscall FUN_10004d50(void *this,byte *param_1);
void __fastcall FUN_10004d80(int param_1);
void __fastcall FUN_10004df0(int param_1);
void __fastcall FUN_10004e20(int *param_1);
void __thiscall FUN_10004f30(void *this,int param_1,float param_2);
void __fastcall FUN_10004f60(int param_1);
void __thiscall FUN_10004fc0(void *this,int param_1,float param_2);
void __thiscall FUN_10004ff0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3);
void __thiscall FUN_10005020(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3);
int __thiscall FUN_10005050(void *this,int param_1,int param_2,int *param_3);
void __thiscall FUN_100050c0(void *this,int param_1,int param_2);
void __thiscall FUN_100050f0(void *this,int param_1);
void __thiscall FUN_10005120(void *this,int param_1,undefined4 *param_2,undefined4 *param_3);
void __fastcall FUN_10005150(void *param_1);
undefined4 __cdecl FUN_10005320(int param_1,int param_2,undefined4 *param_3,undefined4 *param_4);
int __cdecl FUN_10005380(int param_1,undefined4 param_2,int param_3);
int __cdecl FUN_10005400(int param_1,undefined4 param_2,int param_3);
void __cdecl FUN_10005450(int param_1,undefined4 *param_2);
int __cdecl FUN_10005490(int param_1,byte *param_2);
undefined4 __cdecl FUN_100054f0(int param_1);
void __cdecl FUN_10005510(int param_1,byte *param_2);
void __cdecl FUN_100055f0(int param_1,int param_2,float *param_3,float *param_4);
undefined4 __cdecl FUN_100056b0(int param_1,int param_2);
int __cdecl FUN_100056f0(int param_1,int param_2,undefined4 *param_3,float param_4,float param_5,int param_6);
float10 __cdecl FUN_10005840(int param_1,int param_2,int param_3,float param_4);
float10 __cdecl FUN_100059b0(int param_1,int param_2,int param_3,float param_4);
int __cdecl FUN_10005b00(int param_1,int param_2,int param_3,int *param_4);
void __cdecl FUN_10005c10(int param_1,int param_2,int param_3,int param_4);
int __cdecl FUN_10005c70(int param_1,int param_2,int param_3);
void __cdecl monster_apache(int param_1);
void __fastcall FUN_10005e60(int *param_1);
void __thiscall CApache::NullThink(CApache *this);
void __thiscall CApache::StartupUse(CApache *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CApache::DyingThink(CApache *this);
void __thiscall CApache::FlyTouch(CApache *this,CBaseEntity *param_1);
void __thiscall CApache::CrashTouch(CApache *this,CBaseEntity *param_1);
void __thiscall CApache::HuntThink(CApache *this);
float10 __fastcall FUN_10007460(float *param_1);
void __fastcall FUN_10007490(int param_1);
void __fastcall FUN_10007b50(int param_1);
void __thiscall FUN_10007f20(void *this,float *param_1,float *param_2);
undefined4 __fastcall FUN_10007f50(void *param_1);
void __fastcall FUN_10008380(int param_1);
void __cdecl hvr_rocket(int param_1);
void __fastcall FUN_100085e0(int *param_1);
void __thiscall CApacheHVR::IgniteThink(CApacheHVR *this);
void __thiscall CApacheHVR::AccelerateThink(CApacheHVR *this);
void __cdecl monster_barnacle(int param_1);
void __thiscall CBarnacle::BarnacleThink(CBarnacle *this);
void __fastcall FUN_10009190(int *param_1);
void __thiscall CBarnacle::WaitTillDead(CBarnacle *this);
int * __thiscall FUN_10009340(void *this,float *param_1);
void __cdecl monster_barney(int param_1);
void __thiscall FUN_10009580(void *this,int *param_1);
void __fastcall FUN_10009600(int *param_1);
void __fastcall FUN_10009810(void *param_1);
void __fastcall FUN_10009b40(int param_1);
undefined4 __cdecl FUN_10009d80(int param_1,float *param_2);
void __fastcall FUN_1000a1f0(int *param_1);
void __thiscall FUN_1000a3d0(void *this,int param_1);
void __cdecl monster_barney_dead(int param_1);
void __cdecl info_bigmomma(int param_1);
void __thiscall FUN_1000a5f0(void *this,int param_1);
void __cdecl bmortar(int param_1);
void __cdecl monster_bigmomma(int param_1);
void __thiscall FUN_1000b1e0(void *this,undefined4 param_1,float param_2,undefined param_3,undefined param_4,undefined param_5,int param_6,undefined4 param_7);
void __fastcall FUN_1000b380(int param_1);
void __fastcall FUN_1000b4c0(int *param_1);
void __fastcall FUN_1000b530(int param_1);
void __fastcall FUN_1000b890(int param_1);
void __thiscall FUN_1000b8b0(void *this,undefined4 param_1);
void __fastcall FUN_1000b960(int param_1);
undefined4 __fastcall FUN_1000bcc0(int param_1);
undefined4 __fastcall FUN_1000c210(int param_1);
void __thiscall FUN_1000c230(void *this,int *param_1);
void __cdecl FUN_1000c3d0(float *param_1,undefined4 param_2,float *param_3,float param_4,float param_5);
void FUN_1000c550(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4);
void __fastcall FUN_1000c5e0(int param_1);
void __thiscall CBMortar::Animate(CBMortar *this);
undefined4 * __cdecl FUN_1000c830(undefined4 param_1);
void __cdecl monster_bloater(int param_1);
void __thiscall FUN_1000cbd0(void *this,int param_1,int param_2,float param_3,uint param_4);
void __cdecl FUN_1000cd70(float *param_1,int param_2);
void __cdecl func_wall(int param_1);
void __fastcall FUN_1000ce30(int param_1);
void __thiscall FUN_1000ceb0(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl func_wall_toggle(int param_1);
void __fastcall FUN_1000cf40(int param_1);
void __fastcall FUN_1000cf60(int param_1);
void __fastcall FUN_1000cf90(int param_1);
bool __fastcall FUN_1000cfc0(int param_1);
void __thiscall FUN_1000cfe0(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl func_conveyor(int param_1);
void __fastcall FUN_1000d070(void *param_1);
void __thiscall FUN_1000d0f0(void *this,float param_1);
void __cdecl func_illusionary(int param_1);
void __thiscall FUN_1000d200(void *this,int param_1);
void __cdecl func_monsterclip(int param_1);
void __fastcall FUN_1000d320(int param_1);
void __cdecl func_rotating(int param_1);
void __fastcall FUN_1000d7b0(int param_1);
void __thiscall CFuncRotating::HurtTouch(CFuncRotating *this,CBaseEntity *param_1);
void __fastcall FUN_1000da90(int param_1);
void __thiscall CFuncRotating::SpinUp(CFuncRotating *this);
void __thiscall CFuncRotating::SpinDown(CFuncRotating *this);
void __thiscall CFuncRotating::Rotate(CFuncRotating *this);
void __thiscall CFuncRotating::RotatingUse(CFuncRotating *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl func_pendulum(int param_1);
void __thiscall FUN_1000e160(void *this,int param_1);
void __thiscall CPendulum::PendulumUse(CPendulum *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CPendulum::Stop(CPendulum *this);
void __thiscall CPendulum::Swing(CPendulum *this);
void __thiscall CPendulum::RopeTouch(CPendulum *this,CBaseEntity *param_1);
void __cdecl squidspit(int param_1);
void __fastcall FUN_1000e910(int param_1);
void __thiscall CSquidSpit::Animate(CSquidSpit *this);
void __cdecl FUN_1000ea70(int param_1);
void __cdecl monster_bullchicken(int param_1);
uint __fastcall FUN_1000edc0(int param_1);
undefined4 __thiscall FUN_1000f020(void *this,float param_1,float param_2);
void __fastcall FUN_1000feb0(int param_1);
void __fastcall FUN_1000ff20(int *param_1);
void __fastcall FUN_1000fff0(int *param_1);
undefined ** __thiscall FUN_100101a0(void *this,undefined4 param_1);
void __fastcall FUN_10010430(int *param_1);
void __cdecl env_global(int param_1);
void __fastcall FUN_10010600(int param_1);
void __fastcall FUN_10010660(int param_1);
void __cdecl multisource(int param_1);
void __thiscall FUN_10010790(void *this,int param_1);
void __thiscall CMultiSource::Register(CMultiSource *this);
void __fastcall FUN_10010b70(int param_1);
void __thiscall FUN_10010e30(void *this,int param_1);
undefined4 __thiscall FUN_10010f90(void *this,undefined4 param_1,int param_2);
void __cdecl func_button(int param_1);
char * __cdecl FUN_10011320(undefined4 param_1);
void __cdecl FUN_10011410(int param_1,float *param_2);
void __thiscall CBaseButton::ButtonSpark(CBaseButton *this);
void __thiscall CBaseButton::ButtonUse(CBaseButton *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
undefined4 __fastcall FUN_10011690(int param_1);
void __thiscall CBaseButton::ButtonTouch(CBaseButton *this,CBaseEntity *param_1);
void __fastcall FUN_100117f0(void *param_1);
void __thiscall CBaseButton::TriggerAndWait(CBaseButton *this);
void __thiscall CBaseButton::ButtonReturn(CBaseButton *this);
void __thiscall CBaseButton::ButtonBackHome(CBaseButton *this);
void __cdecl func_rot_button(int param_1);
void __cdecl momentary_rot_button(int param_1);
void __thiscall FUN_10012010(void *this,int param_1);
void __fastcall FUN_10012090(int param_1);
void __thiscall FUN_10012190(void *this,float param_1,int param_2);
void __thiscall FUN_10012250(void *this,float param_1);
void __thiscall FUN_100123b0(void *this,undefined4 param_1);
void __thiscall CMomentaryRotButton::Off(CMomentaryRotButton *this);
void __thiscall CMomentaryRotButton::Return(CMomentaryRotButton *this);
void __thiscall FUN_10012500(void *this,float param_1);
void __cdecl env_spark(int param_1);
void __cdecl env_debris(int param_1);
void __fastcall FUN_100126c0(int *param_1);
void __thiscall CEnvSpark::SparkThink(CEnvSpark *this);
void __thiscall CEnvSpark::SparkStart(CEnvSpark *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CEnvSpark::SparkStop(CEnvSpark *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl button_target(int param_1);
void __fastcall FUN_10012940(int param_1);
void __thiscall FUN_100129b0(void *this,undefined4 param_1,undefined4 param_2,int param_3);
undefined4 __cdecl GetEntityAPI(undefined4 *param_1,int param_2);
undefined4 __cdecl GetEntityAPI2(undefined4 *param_1,int *param_2);
undefined4 __cdecl FUN_10012b00(int param_1);
void __cdecl FUN_10012ca0(int param_1,int *param_2);
void __cdecl FUN_10012ce0(int param_1,int param_2);
void __cdecl FUN_10012dd0(int param_1,int param_2);
int __cdecl FUN_10012ed0(int param_1,int param_2);
uint __fastcall FUN_10013360(uint *param_1);
undefined4 __fastcall FUN_100133a0(uint *param_1);
void __thiscall FUN_100133b0(void *this,int param_1);
bool __fastcall FUN_100133e0(uint *param_1);
undefined4 __fastcall FUN_100133f0(uint *param_1);
undefined4 __thiscall FUN_10013400(void *this,float param_1);
undefined4 __thiscall FUN_10013840(void *this,void *param_1);
int __thiscall FUN_10013880(void *this,void *param_1);
void __cdecl FUN_10013970(int param_1);
undefined4 __thiscall FUN_10013b30(void *this,int param_1);
void __fastcall FUN_10013bc0(int param_1);
uint __fastcall FUN_10013c20(int param_1);
undefined4 FUN_10013d30(int param_1,int param_2);
int __cdecl FUN_10013d90(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 param_4);
void __cdecl FUN_10013fa0(int param_1,int param_2);
undefined4 __cdecl FUN_10014290(uint param_1);
undefined4 __cdecl FUN_100142d0(byte *param_1,uint *param_2,undefined *param_3);
undefined4 __thiscall FUN_10014410(uint3 param_1,byte *param_2);
void __cdecl FUN_10014460(int param_1,int param_2);
int __cdecl FUN_10015160(int param_1);
void __cdecl FUN_10015410(int *param_1,int param_2,int param_3);
void FUN_10015560(void);
undefined4 __cdecl FUN_10015ae0(undefined4 *param_1,undefined4 param_2,int param_3,int param_4,byte param_5,int param_6,undefined4 param_7);
void __cdecl FUN_10015f10(int param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,undefined4 param_10,undefined4 param_11);
void __cdecl FUN_100160b0(undefined4 param_1);
void __cdecl FUN_10016280(undefined4 param_1);
void __cdecl FUN_100163a0(undefined4 param_1);
void __fastcall FUN_10016c40(undefined4 *param_1);
void __fastcall FUN_10016c50(int param_1);
void __cdecl FUN_100170d0(int param_1);
void __cdecl FUN_100174c0(int param_1,int param_2,int param_3);
void __fastcall FUN_10017950(int *param_1);
int __fastcall FUN_10017c90(void *param_1);
undefined4 __thiscall FUN_10017d60(void *this,int param_1);
void __fastcall FUN_10017d90(int *param_1);
void __thiscall FUN_10017e70(void *this,undefined4 param_1,int param_2);
void __thiscall CBaseEntity::SUB_StartFadeOut(CBaseEntity *this);
void __thiscall CBaseEntity::SUB_FadeOut(CBaseEntity *this);
void __thiscall CGib::WaitTillLand(CGib *this);
void __thiscall CGib::BounceGibTouch(CGib *this,CBaseEntity *param_1);
void __thiscall CGib::StickyGibTouch(CGib *this,CBaseEntity *param_1);
void __thiscall FUN_10018420(void *this,undefined4 param_1);
undefined4 __thiscall FUN_10018530(void *this,float param_1,uint param_2);
undefined4 __thiscall FUN_10018580(void *this,int param_1,int param_2,float param_3,uint param_4);
undefined4 __thiscall FUN_10018ac0(void *this,int param_1,undefined4 param_2,float param_3,uint param_4);
float10 __thiscall FUN_10018cd0(void *this,float param_1);
void __cdecl FUN_10018d10(float param_1,float param_2,float param_3,float param_4,float param_5,float param_6,float param_7,int param_8,undefined4 param_9);
void __thiscall FUN_10018fb0(void *this,float *param_1);
void __thiscall FUN_10019030(void *this,float param_1,float param_2,float param_3,int param_4,undefined4 param_5);
void FUN_10019080(undefined param_1,undefined param_2,undefined param_3,float param_4,float param_5,float param_6,int param_7,undefined4 param_8);
int * __thiscall FUN_100190d0(void *this,int param_1,int param_2,undefined4 param_3);
void __thiscall FUN_100194d0(void *this,undefined4 param_1,float param_2,float param_3,float param_4,float param_5,int param_6,uint param_7);
void __thiscall FUN_100195a0(void *this,undefined4 param_1,float param_2);
void __thiscall FUN_10019690(void *this,uint param_1,float param_2,float param_3,float param_4,float param_5,float param_6,float param_7,float param_8,float param_9,undefined4 param_10,float param_11,float param_12,int param_13,int param_14,float param_15);
void __thiscall FUN_10019d90(void *this,float *param_1,uint param_2,float param_3,float param_4,float param_5,float param_6,float param_7,float param_8,float param_9,float param_10,undefined4 param_11,float param_12,float param_13,undefined4 param_14,int param_15,float param_16,int param_17);
void __cdecl monster_alien_controller(int param_1);
void __thiscall FUN_1001a6c0(void *this,int param_1,int param_2,float param_3,uint param_4);
void __thiscall FUN_1001a700(void *this,undefined4 param_1,int param_2);
void __fastcall FUN_1001a750(int *param_1);
void __fastcall FUN_1001a8a0(int param_1);
void __thiscall FUN_1001aec0(void *this,int *param_1);
void __cdecl FUN_1001b030(float *param_1,float param_2,float param_3,float param_4,float param_5,float param_6,float param_7,float param_8,float param_9,float param_10,float param_11);
void __fastcall FUN_1001b220(void *param_1);
undefined ** __thiscall FUN_1001b920(void *this,undefined4 param_1);
void __fastcall FUN_1001bcb0(int *param_1);
void __cdecl controller_head_ball(int param_1);
void __thiscall CControllerHeadBall::HuntThink(CControllerHeadBall *this);
void __thiscall CControllerHeadBall::DieThink(CControllerHeadBall *this);
void __thiscall FUN_1001ca60(void *this,float param_1,float param_2,float param_3);
void __thiscall CControllerHeadBall::BounceTouch(CControllerHeadBall *this,CBaseEntity *param_1);
void __cdecl controller_energy_ball(int param_1);
void __thiscall CControllerZapBall::AnimateThink(CControllerZapBall *this);
void __thiscall CControllerZapBall::ExplodeTouch(CControllerZapBall *this,CBaseEntity *param_1);
void __cdecl crossbow_bolt(int param_1);
undefined4 * FUN_1001d360(void);
void __fastcall FUN_1001d3d0(int *param_1);
void __thiscall CCrossbowBolt::BoltTouch(CCrossbowBolt *this,CBaseEntity *param_1);
void __thiscall CCrossbowBolt::BubbleThink(CCrossbowBolt *this);
void __thiscall CCrossbowBolt::ExplodeThink(CCrossbowBolt *this);
void __cdecl weapon_crossbow(int param_1);
void __fastcall FUN_1001da90(int *param_1);
void __fastcall FUN_1001dc60(int *param_1);
void __fastcall FUN_1001dcc0(int *param_1);
void __fastcall FUN_1001e1c0(int param_1);
void __fastcall FUN_1001e250(int *param_1);
void __cdecl ammo_crossbow(int param_1);
void __fastcall FUN_1001e440(int *param_1);
undefined4 __thiscall FUN_1001e490(void *this,int *param_1);
undefined4 __cdecl FUN_1001e4e0(int param_1);
void __cdecl weapon_crowbar(int param_1);
void __fastcall FUN_1001e5d0(int *param_1);
void __fastcall FUN_1001e700(int *param_1);
void __cdecl FUN_1001e730(float *param_1,undefined4 *param_2,float *param_3,int param_4);
void __thiscall CCrowbar::Smack(CCrowbar *this);
void __thiscall CCrowbar::SwingAgain(CCrowbar *this);
undefined4 __fastcall FUN_1001e990(int *param_1);
void __thiscall FUN_1001ef50(void *this,byte *param_1);
undefined4 __thiscall FUN_1001ef70(void *this,byte *param_1,int param_2,int param_3);
undefined ** __thiscall FUN_1001f000(void *this,undefined4 param_1);
void __cdecl FUN_1001f310(int param_1,int *param_2,int param_3,float param_4);
void __thiscall FUN_1001f530(void *this,int param_1);
void __cdecl func_door(int param_1);
void __cdecl func_water(int param_1);
void __fastcall FUN_1001fa10(int param_1);
void __thiscall CBaseDoor::DoorTouch(CBaseDoor *this,CBaseEntity *param_1);
undefined4 __fastcall FUN_1001ffe0(CBaseDoor *param_1);
void __thiscall CBaseDoor::DoorGoUp(CBaseDoor *this);
void __thiscall CBaseDoor::DoorHitTop(CBaseDoor *this);
void __thiscall CBaseDoor::DoorGoDown(CBaseDoor *this);
void __thiscall CBaseDoor::DoorHitBottom(CBaseDoor *this);
void __cdecl func_door_rotating(int param_1);
void __cdecl momentary_door(int param_1);
void __fastcall FUN_10020be0(int *param_1);
void __fastcall FUN_10020d80(int param_1);
void __thiscall FUN_10020eb0(void *this,int param_1);
void __thiscall CMomentaryDoor::DoorMoveDone(CMomentaryDoor *this);
void __cdecl info_target(int param_1);
void __cdecl env_bubbles(int param_1);
void __thiscall FUN_100213c0(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __thiscall FUN_10021420(void *this,int param_1);
void __thiscall CBubbling::FizzThink(CBubbling *this);
void __cdecl beam(int param_1);
void __fastcall FUN_10021680(void *param_1);
void __thiscall FUN_100216d0(void *this,uint param_1);
void __thiscall FUN_10021720(void *this,uint param_1);
int __fastcall FUN_10021770(int param_1);
int __fastcall FUN_100217b0(int param_1);
undefined4 * __cdecl FUN_10021800(int param_1,int param_2);
void __thiscall FUN_10021880(void *this,int param_1,int param_2);
void __thiscall FUN_10021940(void *this,undefined4 *param_1,undefined4 *param_2);
void __thiscall FUN_10021a40(void *this,undefined4 *param_1,uint param_2);
void __thiscall FUN_10021ac0(void *this,uint param_1,uint param_2);
void __fastcall FUN_10021b30(int param_1);
void __thiscall CBeam::TriggerTouch(CBeam *this,CBaseEntity *param_1);
int FUN_10021d00(undefined4 param_1);
void __thiscall FUN_10021d50(void *this,undefined4 *param_1,undefined4 param_2,undefined4 *param_3);
void __cdecl env_lightning(int param_1);
void __cdecl env_beam(int param_1);
void __fastcall FUN_10021e90(int *param_1);
void __thiscall FUN_10022010(void *this,int param_1);
void __thiscall CLightning::ToggleUse(CLightning *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CLightning::StrikeUse(CLightning *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
undefined4 __cdecl FUN_10022350(int param_1);
void __thiscall CLightning::StrikeThink(CLightning *this);
void __thiscall FUN_10022790(void *this,int param_1);
void __thiscall CLightning::DamageThink(CLightning *this);
void __thiscall FUN_100228d0(void *this,undefined4 *param_1,undefined4 *param_2);
void __fastcall FUN_10022a00(void *param_1);
void __thiscall FUN_10022e00(void *this,float *param_1);
void __fastcall FUN_10022fa0(void *param_1);
void __cdecl env_laser(int param_1);
void __fastcall FUN_10023260(int *param_1);
void __fastcall FUN_100233c0(int param_1);
void __thiscall FUN_10023410(void *this,int param_1);
bool __fastcall FUN_100235f0(int param_1);
void __fastcall FUN_10023610(int param_1);
void __fastcall FUN_10023640(int param_1);
void __thiscall FUN_10023690(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __thiscall FUN_100236d0(void *this,int param_1);
void __thiscall CLaser::StrikeThink(CLaser *this);
void __cdecl env_glow(int param_1);
void __fastcall FUN_100239c0(int param_1,undefined param_2,undefined4 param_3);
void __cdecl env_sprite(int param_1);
void __fastcall FUN_10023bb0(int param_1);
void __thiscall FUN_10023c40(void *this,int param_1,undefined4 *param_2);
undefined4 * __cdecl FUN_10023c80(int param_1,undefined4 *param_2,int param_3);
void __thiscall CSprite::AnimateThink(CSprite *this);
void __thiscall CSprite::AnimateUntilDead(CSprite *this);
void __thiscall FUN_10023dc0(void *this,undefined4 param_1,undefined4 param_2);
void __thiscall CSprite::ExpandThink(CSprite *this);
void __thiscall FUN_10023e80(void *this,float param_1);
void __fastcall FUN_10023ef0(int param_1);
void __fastcall FUN_10023f10(int param_1);
void __thiscall FUN_10023f90(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl gibshooter(int param_1);
void __thiscall FUN_100240d0(void *this,int param_1);
void __fastcall FUN_100241d0(int *param_1);
void __thiscall CGibShooter::ShootThink(CGibShooter *this);
void __cdecl env_shooter(int param_1);
void __thiscall FUN_10024670(void *this,int param_1);
undefined4 * __fastcall FUN_100247a0(int param_1);
void __cdecl test_effect(int param_1);
void __thiscall CTestEffect::TestThink(CTestEffect *this);
void __cdecl env_blood(int param_1);
void __thiscall FUN_10024c70(void *this,int param_1);
float * __thiscall FUN_10024d20(void *this,float *param_1);
void __thiscall FUN_10024d60(void *this,float *param_1,int *param_2);
void __cdecl env_shake(int param_1);
void __thiscall FUN_10025050(void *this,int param_1);
void __cdecl env_fade(int param_1);
void __thiscall FUN_10025200(void *this,int param_1);
void __thiscall FUN_10025290(void *this,int *param_1);
void __cdecl env_message(int param_1);
void __fastcall FUN_100253b0(int *param_1);
void __thiscall FUN_10025470(void *this,int param_1);
void __thiscall FUN_10025540(void *this,int *param_1);
void __cdecl env_funnel(int param_1);
void __fastcall FUN_10025740(int *param_1);
void __cdecl env_beverage(int param_1);
void __fastcall FUN_100257e0(int param_1);
void __fastcall FUN_10025890(int *param_1);
void __cdecl item_sodacan(int param_1);
void __thiscall CItemSoda::CanThink(CItemSoda *this);
void __thiscall CItemSoda::CanTouch(CItemSoda *this,CBaseEntity *param_1);
void __cdecl weapon_egon(int param_1);
void __fastcall FUN_10025b60(int *param_1);
void __fastcall FUN_10025ce0(int *param_1);
float10 FUN_10025d90(void);
float10 FUN_10025da0(void);
bool __fastcall FUN_10025db0(int param_1);
void __thiscall FUN_10025dc0(void *this,int param_1);
void __thiscall FUN_10026040(void *this,float *param_1,undefined4 *param_2);
void __thiscall FUN_10026500(void *this,undefined4 param_1,undefined4 *param_2);
void __fastcall FUN_10026730(int param_1);
void __fastcall FUN_10026a50(int param_1);
void __fastcall FUN_10026b90(int param_1);
void __cdecl ammo_egonclip(int param_1);
void __fastcall FUN_10026c70(int *param_1);
undefined4 __thiscall FUN_10026cc0(void *this,int *param_1);
void __cdecl spark_shower(int param_1);
void __fastcall FUN_10026f00(int param_1);
void __cdecl env_explosion(int param_1);
void __thiscall FUN_100270f0(void *this,int param_1);
void __thiscall CEnvExplosion::Smoke(CEnvExplosion *this);
void __cdecl FUN_10027510(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,int param_4);
void __fastcall FUN_10027710(int *param_1);
void __thiscall FUN_10027770(void *this,float param_1);
void __thiscall FUN_100278b0(void *this,int *param_1);
void __fastcall FUN_10027910(int *param_1,undefined param_2,undefined4 param_3);
undefined4 __thiscall FUN_10027d90(void *this,float *param_1,float *param_2,float *param_3);
void __thiscall FUN_10027fd0(void *this,int param_1);
void __cdecl func_breakable(int param_1);
void __thiscall FUN_100281f0(void *this,void *param_1);
void __thiscall FUN_10028220(void *this,void *param_1);
void __fastcall FUN_10028250(int *param_1);
undefined ** __cdecl FUN_10028320(undefined4 param_1,undefined4 *param_2);
void __cdecl FUN_100283c0(undefined4 param_1);
void __cdecl FUN_10028400(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void __fastcall FUN_10028460(char *param_1);
void __fastcall FUN_100285f0(int param_1);
void __thiscall CBreakable::BreakTouch(CBreakable *this,CBaseEntity *param_1);
void __fastcall FUN_100288a0(CBreakable *param_1);
void __thiscall CBreakable::Die(CBreakable *this);
bool __fastcall FUN_10029160(int param_1);
void __cdecl func_pushable(int param_1);
void __fastcall FUN_10029260(int *param_1);
void __fastcall FUN_10029370(char *param_1);
void __thiscall FUN_10029590(void *this,int *param_1);
void __thiscall FUN_10029660(void *this,int *param_1,int param_2);
void __thiscall FUN_10029880(void *this,void *param_1);
void __thiscall FUN_100298b0(void *this,void *param_1);
void __fastcall FUN_10029b50(int param_1);
void __thiscall FUN_10029bc0(void *this,int param_1);
undefined4 __thiscall FUN_1002a050(void *this,int param_1);
void __fastcall FUN_1002a120(int param_1);
void __fastcall FUN_1002a1a0(int *param_1);
void __thiscall FUN_1002a340(void *this,int *param_1,undefined4 param_2,int param_3,float param_4);
undefined4 FUN_1002a430(undefined4 param_1);
undefined4 __thiscall FUN_1002a440(void *this,float param_1);
void __fastcall FUN_1002a490(int *param_1);
void __fastcall FUN_1002a500(int *param_1);
void __thiscall FUN_1002ac60(void *this,float *param_1,float param_2);
void __thiscall FUN_1002ad10(void *this,undefined4 *param_1);
void FUN_1002af50(void);
void __fastcall FUN_1002b0d0(int param_1);
void __fastcall FUN_1002b130(int param_1);
void __cdecl func_tank(int param_1);
void __thiscall FUN_1002b220(void *this,undefined4 *param_1,undefined4 *param_2,float param_3);
void __cdecl func_tanklaser(int param_1);
void __fastcall FUN_1002b3f0(int param_1);
void __thiscall FUN_1002b420(void *this,int param_1);
int __fastcall FUN_1002b470(int param_1);
void __fastcall FUN_1002b510(int *param_1);
void __cdecl func_tankrocket(int param_1);
void __thiscall FUN_1002b6f0(void *this,undefined4 *param_1);
void __cdecl func_tankmortar(int param_1);
void __thiscall FUN_1002b7d0(void *this,int param_1);
void __cdecl func_tankcontrols(int param_1);
void __fastcall FUN_1002b9d0(int param_1);
void __fastcall FUN_1002ba80(int param_1);
void FUN_1002c760(int *param_1);
undefined4 __thiscall FUN_1002c860(void *this,void *param_1,int *param_2);
void FUN_1002c8d0(void);
undefined4 * FUN_1002ce60(void);
void __cdecl streak_spiral(int param_1);
void __cdecl garg_stomp(int param_1);
undefined4 * __cdecl FUN_1002cfc0(float *param_1,float *param_2,undefined4 param_3);
void __fastcall FUN_1002d0e0(int param_1);
void FUN_1002d550(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6);
void __cdecl monster_gargantua(int param_1);
void __thiscall FUN_1002d760(void *this,undefined4 param_1);
void __fastcall FUN_1002d770(int param_1);
void __fastcall FUN_1002d780(int param_1);
void __fastcall FUN_1002d810(void *param_1);
void __fastcall FUN_1002d9e0(void *param_1);
void __thiscall FUN_1002dc00(void *this,float param_1,float param_2);
void __fastcall FUN_1002dce0(void *param_1);
void FUN_1002dff0(float param_1,float param_2,float param_3,float param_4,float param_5,float param_6,undefined4 param_7,undefined4 param_8,float param_9,int param_10);
void __fastcall FUN_1002e410(int param_1);
void __thiscall FUN_1002e840(void *this,undefined4 param_1,float param_2);
void __fastcall FUN_1002ea10(int param_1);
void __thiscall FUN_1002eb80(void *this,undefined4 param_1);
int * __thiscall FUN_1002ef30(void *this,int param_1,int param_2,undefined4 param_3);
undefined ** __thiscall FUN_1002f080(void *this,int param_1);
void __cdecl env_smoker(int param_1);
void __fastcall FUN_1002f650(int param_1);
void __fastcall FUN_1002f6d0(int param_1);
void __fastcall FUN_1002f820(int param_1);
undefined4 * __cdecl FUN_1002f8a0(undefined4 *param_1,undefined4 param_2,undefined4 param_3,float param_4);
void __cdecl FUN_1002fb80(float param_1,float param_2,undefined4 param_3,float param_4,undefined4 param_5,undefined4 param_6);
void __cdecl weapon_gauss(int param_1);
float10 FUN_1002fcb0(void);
void __fastcall FUN_1002fcd0(int *param_1);
void __fastcall FUN_1002fee0(int *param_1);
void __fastcall FUN_1002ff50(int *param_1);
void __fastcall FUN_100304f0(void *param_1);
void __thiscall FUN_100306d0(void *this,float param_1,float param_2,float param_3,float param_4,float param_5,float param_6,float param_7);
void __cdecl ammo_gaussclip(int param_1);
void __fastcall FUN_10031010(int *param_1);
undefined4 __thiscall FUN_10031060(void *this,int *param_1);
void __cdecl monster_generic(int param_1);
void __cdecl grenade(int param_1);
void __fastcall FUN_10031330(void *param_1);
void __thiscall FUN_10031390(void *this,int param_1,undefined4 param_2);
void __thiscall CGrenade::Smoke(CGrenade *this);
void __thiscall CGrenade::DetonateUse(CGrenade *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CGrenade::PreDetonate(CGrenade *this);
void __thiscall CGrenade::Detonate(CGrenade *this);
void __thiscall CGrenade::ExplodeTouch(CGrenade *this,CBaseEntity *param_1);
void __thiscall CGrenade::DangerSoundThink(CGrenade *this);
void __thiscall CGrenade::BounceTouch(CGrenade *this,CBaseEntity *param_1);
void __thiscall CGrenade::SlideTouch(CGrenade *this,CBaseEntity *param_1);
void __thiscall CGrenade::TumbleThink(CGrenade *this);
void __fastcall FUN_10032040(int param_1);
undefined4 * __cdecl FUN_100320f0(int param_1);
undefined4 * __cdecl FUN_10032200(int param_1);
void __cdecl monster_gman(int param_1);
void __thiscall FUN_10032850(void *this,int *param_1);
undefined4 __cdecl FUN_10032b50(int param_1,int param_2,float *param_3,float param_4);
undefined4 * __cdecl FUN_10032cb0(undefined4 *param_1,int param_2,float *param_3,float param_4,float param_5,float param_6,float param_7);
void __cdecl FUN_10033150(float *param_1,undefined4 param_2,float *param_3,float param_4,float param_5,float param_6,float param_7,float param_8);
void __cdecl func_recharge(int param_1);
void __thiscall FUN_100333d0(void *this,int param_1);
void __fastcall FUN_10033480(int *param_1);
void __thiscall CRecharge::Recharge(CRecharge *this);
void __thiscall CRecharge::Off(CRecharge *this);
void __cdecl monster_cine_scientist(int param_1);
void __cdecl monster_cine_panther(int param_1);
void __cdecl monster_cine_barney(int param_1);
void __cdecl monster_cine2_scientist(int param_1);
void __cdecl monster_cine2_hvyweapons(int param_1);
void __cdecl monster_cine2_slave(int param_1);
void __cdecl monster_cine3_scientist(int param_1);
void __cdecl monster_cine3_barney(int param_1);
void __thiscall FUN_10033b50(void *this,undefined4 param_1);
void __fastcall FUN_10033c80(int param_1);
void __thiscall CLegacyCineMonster::CineThink(CLegacyCineMonster *this);
void __cdecl cine_blood(int param_1);
void __thiscall CCineBlood::BloodGush(CCineBlood *this);
void __thiscall CCineBlood::BloodStart(CCineBlood *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl cycler(int param_1);
void __fastcall FUN_100340e0(void *param_1);
void __cdecl cycler_prdroid(int param_1);
void __thiscall FUN_10034210(void *this,char *param_1);
void __fastcall FUN_100342c0(int *param_1);
undefined4 __fastcall FUN_10034460(void *param_1);
void __cdecl cycler_sprite(int param_1);
void __fastcall FUN_100346a0(void *param_1);
void __thiscall FUN_10034770(void *this,float param_1);
void __cdecl cycler_weapon(int param_1);
undefined4 __fastcall FUN_10034920(int *param_1);
void __fastcall FUN_10034970(int param_1);
void __fastcall FUN_10034990(int *param_1);
void __cdecl cycler_wreckage(int param_1);
void __fastcall FUN_10034b20(int param_1);
undefined4 FUN_10034d70(void);
void GiveFnptrsToDll(undefined4 *param_1,undefined4 param_2);
void __cdecl weapon_handgrenade(int param_1);
void __fastcall FUN_10034e10(int *param_1);
void __fastcall FUN_10034f50(int *param_1);
void __fastcall FUN_10034ff0(int *param_1);
void __cdecl monster_human_assassin(int param_1);
void __thiscall FUN_10035520(void *this,float param_1);
void __fastcall FUN_100362a0(int *param_1);
undefined ** __thiscall FUN_10036430(void *this,undefined4 param_1);
void __cdecl monster_headcrab(int param_1);
void __fastcall FUN_100369c0(int *param_1);
void __thiscall CHeadCrab::LeapTouch(CHeadCrab *this,CBaseEntity *param_1);
void __fastcall FUN_10036c70(int *param_1);
void __fastcall FUN_10036db0(int *param_1);
void __fastcall FUN_10036e00(int *param_1);
void __fastcall FUN_10036e50(int *param_1);
void __fastcall FUN_10036ea0(int *param_1);
undefined ** __thiscall FUN_10036ef0(void *this,int param_1);
void __cdecl monster_babycrab(int param_1);
void __cdecl item_healthkit(int param_1);
void __fastcall FUN_10037160(int *param_1);
undefined4 __thiscall FUN_100371b0(void *this,int *param_1);
void __cdecl func_healthcharger(int param_1);
void __thiscall FUN_10037350(void *this,int param_1);
void __fastcall FUN_10037400(int *param_1);
void __thiscall FUN_100374c0(void *this,int *param_1);
void __thiscall CWallHealth::Recharge(CWallHealth *this);
void __thiscall CWallHealth::Off(CWallHealth *this);
void __cdecl monster_human_grunt(int param_1);
void __fastcall FUN_10037820(int param_1);
undefined4 __thiscall FUN_10037880(void *this,int *param_1);
undefined4 __fastcall FUN_10037af0(int param_1);
void __fastcall FUN_10037b30(int param_1);
void __fastcall FUN_10037b60(int param_1);
void __fastcall FUN_100383a0(int param_1);
undefined4 FUN_10038540(void);
void __thiscall FUN_10038650(void *this,float param_1);
void __thiscall FUN_10038850(void *this,float param_1);
void __thiscall FUN_100395c0(void *this,int param_1);
void __fastcall FUN_10039780(int *param_1);
undefined ** __thiscall FUN_10039c20(void *this,int param_1);
void __cdecl monster_grunt_repel(int param_1);
void __fastcall FUN_10039f80(int *param_1);
void __thiscall CHGruntRepel::RepelUse(CHGruntRepel *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall FUN_1003a170(void *this,int param_1);
void __cdecl monster_hgrunt_dead(int param_1);
void __cdecl weapon_glock(int param_1);
void __cdecl weapon_9mmhandgun(int param_1);
void __fastcall FUN_1003a400(int *param_1);
void __thiscall FUN_1003a5d0(void *this,float param_1,int param_2);
void __cdecl ammo_glockclip(int param_1);
void __fastcall FUN_1003a9a0(int *param_1);
undefined4 __thiscall FUN_1003a9f0(void *this,int *param_1);
void __cdecl ammo_9mmclip(int param_1);
void __cdecl hornet(int param_1);
void __thiscall CHornet::StartTrack(CHornet *this);
void __thiscall CHornet::StartDart(CHornet *this);
void __fastcall FUN_1003ae90(int param_1);
void __thiscall CHornet::TrackTarget(CHornet *this);
void __thiscall CHornet::TrackTouch(CHornet *this,CBaseEntity *param_1);
void __thiscall CHornet::DartTouch(CHornet *this,CBaseEntity *param_1);
void __thiscall CHornet::DieTouch(CHornet *this,CBaseEntity *param_1);
void __cdecl weapon_hornetgun(int param_1);
void __fastcall FUN_1003b970(int *param_1);
void __fastcall FUN_1003bb20(int *param_1);
void __fastcall FUN_1003c730(int *param_1);
void __cdecl monster_houndeye(int param_1);
void __thiscall FUN_1003ca30(void *this,int param_1);
void __fastcall FUN_1003cec0(int param_1);
void __fastcall FUN_1003cf30(int param_1);
void __fastcall FUN_1003cfd0(int param_1);
void __fastcall FUN_1003d1d0(int param_1);
void __fastcall FUN_1003d280(int *param_1);
void __thiscall FUN_1003d670(void *this,int *param_1);
void __thiscall FUN_1003d7c0(void *this,int *param_1);
undefined ** __thiscall FUN_1003db90(void *this,int param_1);
void __cdecl monster_ichthyosaur(int param_1);
void __fastcall FUN_1003e030(int param_1);
void __fastcall FUN_1003e080(int param_1);
void __thiscall CIchthyosaur::BiteTouch(CIchthyosaur *this,CBaseEntity *param_1);
void __thiscall CIchthyosaur::CombatUse(CIchthyosaur *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall FUN_1003ea70(void *this,int *param_1);
float10 __fastcall FUN_1003f300(int param_1);
void __fastcall FUN_1003f5f0(int *param_1);
void __fastcall FUN_1003f6d0(int *param_1);
float * __thiscall FUN_10040130(void *this,float *param_1,float *param_2);
void __cdecl monster_alien_slave(int param_1);
void __cdecl monster_vortigaunt(int param_1);
void __thiscall FUN_100405a0(void *this,undefined4 param_1,float param_2,undefined4 param_3,undefined4 param_4,undefined4 *param_5);
void __fastcall FUN_10040690(void *param_1);
void __thiscall FUN_100407f0(void *this,undefined4 param_1,int param_2);
void __thiscall FUN_10040de0(void *this,int *param_1);
undefined4 __thiscall FUN_10040ff0(void *this,int param_1,int param_2,float param_3,uint param_4);
void __fastcall FUN_100410e0(int *param_1);
void __thiscall FUN_100411f0(void *this,int param_1);
void __fastcall FUN_10041630(int param_1);
void __thiscall FUN_100416a0(void *this,undefined4 param_1,int *param_2);
void __thiscall FUN_100417e0(void *this,int param_1);
void __fastcall FUN_10041b90(int param_1);
void __thiscall FUN_10041c00(void *this,int param_1,int param_2,int param_3);
void __cdecl world_items(int param_1);
void __thiscall FUN_10041c80(void *this,int param_1);
void __fastcall FUN_10041cd0(int param_1);
void __fastcall FUN_10041db0(int param_1);
void __thiscall CItem::ItemTouch(CItem *this,CBaseEntity *param_1);
void __thiscall CItem::Materialize(CItem *this);
void __cdecl item_suit(int param_1);
void __fastcall FUN_10042050(int *param_1);
undefined4 __thiscall FUN_10042090(void *this,int param_1);
void __cdecl item_battery(int param_1);
void __fastcall FUN_10042150(int *param_1);
void __cdecl item_antidote(int param_1);
void __fastcall FUN_10042340(int *param_1);
undefined4 FUN_10042380(void *param_1);
void __cdecl item_security(int param_1);
void __fastcall FUN_10042400(int *param_1);
void __cdecl item_longjump(int param_1);
void __fastcall FUN_100424b0(int *param_1);
undefined4 __thiscall FUN_100424f0(void *this,int param_1);
void __cdecl monster_leech(int param_1);
void __fastcall FUN_10042770(int *param_1);
void __fastcall FUN_100428c0(int param_1);
void __fastcall FUN_100429d0(int *param_1);
undefined4 __thiscall FUN_10042aa0(void *this,int *param_1);
void __fastcall FUN_10042ad0(int param_1);
void FUN_10042e80(void);
float10 __thiscall FUN_10042ec0(void *this,int param_1);
void __thiscall CLeech::DeadThink(CLeech *this);
void __fastcall FUN_10043380(int *param_1);
void __thiscall CLeech::SwimThink(CLeech *this);
void __cdecl light(int param_1);
void __thiscall FUN_10043e30(void *this,int param_1);
void __fastcall FUN_10043ee0(int param_1);
void __thiscall FUN_10043f60(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl light_spot(int param_1);
void __cdecl light_environment(int param_1);
void __thiscall FUN_100442f0(void *this,void *param_1);
void __thiscall FUN_10044320(void *this,void *param_1);
void __fastcall FUN_10044350(int param_1);
void __thiscall FUN_10044380(void *this,int param_1);
bool __thiscall FUN_100443d0(void *this,undefined4 param_1);
void __fastcall FUN_10044400(int param_1);
void __cdecl game_score(int param_1);
void __thiscall FUN_100444c0(void *this,int param_1);
void __thiscall FUN_10044520(void *this,int *param_1);
void __cdecl game_end(int param_1);
void __cdecl game_text(int param_1);
void __thiscall FUN_100446a0(void *this,int param_1);
void __cdecl game_team_master(int param_1);
void __thiscall FUN_100449e0(void *this,int param_1);
undefined4 __thiscall FUN_10044b60(void *this,int *param_1);
void __cdecl game_team_set(int param_1);
void __cdecl game_zone_player(int param_1);
void __thiscall FUN_10044d00(void *this,int param_1);
void __cdecl game_player_hurt(int param_1);
void __thiscall FUN_10044fa0(void *this,int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void __cdecl game_counter(int param_1);
void __thiscall FUN_100450b0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void __cdecl game_counter_set(int param_1);
void __cdecl game_player_equip(int param_1);
void __thiscall FUN_10045340(void *this,int *param_1);
void __cdecl game_player_team(int param_1);
undefined4 FUN_10045400(undefined4 param_1);
void __cdecl monstermaker(int param_1);
void __thiscall FUN_100455a0(void *this,int param_1);
void __fastcall FUN_10045660(int *param_1);
void __fastcall FUN_10045730(int param_1);
void __thiscall CMonsterMaker::CyclicUse(CMonsterMaker *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CMonsterMaker::ToggleUse(CMonsterMaker *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CMonsterMaker::MakerThink(CMonsterMaker *this);
void __thiscall FUN_10045a20(void *this,void *param_1);
undefined4 __thiscall FUN_10045a50(void *this,void *param_1);
void __thiscall FUN_10045ac0(void *this,float param_1);
undefined4 __fastcall FUN_10045ae0(int param_1);
void __fastcall FUN_10045b00(int *param_1);
void __fastcall FUN_10045b60(int *param_1);
float10 __thiscall FUN_10045cb0(void *this,float *param_1);
void __fastcall FUN_100460c0(int *param_1);
void __thiscall CBaseMonster::MonsterUse(CBaseMonster *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
uint __fastcall FUN_10046180(int param_1);
void __fastcall FUN_100461c0(int param_1);
void __fastcall FUN_100461f0(int param_1);
undefined4 __fastcall FUN_10046200(int param_1);
undefined4 __fastcall FUN_10046230(void *param_1);
void __thiscall FUN_100463e0(void *this,undefined4 param_1,undefined4 param_2,undefined4 *param_3);
void __thiscall FUN_10046430(void *this,undefined4 param_1,undefined4 param_2);
undefined4 __cdecl FUN_100464b0(uint param_1);
void __thiscall FUN_100464d0(void *this,undefined4 param_1);
void __thiscall FUN_10046a30(void *this,int param_1,undefined4 param_2);
undefined4 __thiscall FUN_10046bb0(void *this,int *param_1);
void __thiscall FUN_10046f20(void *this,int param_1,undefined4 *param_2);
undefined4 __fastcall FUN_10046fa0(int param_1);
void __thiscall FUN_10047030(void *this,int param_1);
void __thiscall FUN_100470f0(void *this,byte *param_1);
float10 __thiscall FUN_10047350(void *this,int param_1);
void __thiscall FUN_10047490(void *this,float param_1);
undefined4 FUN_100475f0(byte param_1);
undefined4 __thiscall FUN_10047640(void *this,float *param_1,uint param_2,undefined4 param_3);
void __thiscall FUN_100477b0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4);
void __fastcall FUN_10048150(int *param_1);
void __thiscall FUN_10048620(void *this,undefined4 param_1,undefined4 param_2,float param_3);
void __fastcall FUN_100486d0(int param_1);
void __thiscall CBaseMonster::MonsterInitThink(CBaseMonster *this);
void __fastcall FUN_10048800(int *param_1);
void __fastcall FUN_10048a70(int param_1);
undefined4 __fastcall FUN_10048af0(int param_1);
undefined4 __thiscall FUN_10048b10(void *this,int *param_1);
void __fastcall FUN_100491a0(int param_1,undefined param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
float10 __fastcall FUN_10049290(int param_1);
float10 __thiscall FUN_100492e0(void *this,float param_1);
float10 __thiscall FUN_10049490(void *this,float param_1,float param_2,float param_3);
void __fastcall FUN_100494e0(int param_1);
void __thiscall FUN_10049590(void *this,int *param_1);
undefined4 __thiscall FUN_10049910(void *this,float param_1,float param_2,float param_3);
int __fastcall FUN_10049a40(int *param_1);
void __fastcall FUN_10049ba0(int *param_1);
void __thiscall FUN_10049e40(void *this,int param_1);
undefined4 __fastcall FUN_10049ed0(int *param_1);
undefined4 __thiscall FUN_1004a060(void *this,int param_1,int param_2);
undefined4 __thiscall FUN_1004a0c0(void *this,float *param_1,float *param_2);
void __thiscall FUN_1004a370(void *this,undefined4 *param_1,float *param_2);
undefined4 __fastcall FUN_1004a490(int param_1);
void __thiscall FUN_1004a530(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void __thiscall CBaseMonster::CorpseFallThink(CBaseMonster *this);
void __fastcall FUN_1004a5d0(int *param_1);
undefined4 __fastcall FUN_1004a680(int param_1);
bool __fastcall FUN_1004a980(int *param_1);
int __thiscall FUN_1004aac0(void *this,int param_1,undefined4 *param_2,undefined4 *param_3);
void __thiscall FUN_1004abb0(void *this,int param_1);
void __fastcall FUN_1004ac00(int *param_1);
int __fastcall FUN_1004ad30(int *param_1);
void __cdecl func_mortar_field(int param_1);
void __thiscall FUN_1004afd0(void *this,int param_1);
void __fastcall FUN_1004b0e0(int *param_1);
void __thiscall CFuncMortarField::FieldUse(CFuncMortarField *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl monster_mortar(int param_1);
void __thiscall CMortar::MortarExplode(CMortar *this);
void __cdecl weapon_mp5(int param_1);
void __cdecl weapon_9mmAR(int param_1);
void __fastcall FUN_1004b6f0(int *param_1);
void __cdecl ammo_mp5clip(int param_1);
void __fastcall FUN_1004be20(int *param_1);
void * __thiscall FUN_1004be70(void *this,int *param_1);
void __cdecl ammo_9mmAR(int param_1);
void __cdecl ammo_9mmbox(int param_1);
void __fastcall FUN_1004bf70(int *param_1);
void * __thiscall FUN_1004bfc0(void *this,int *param_1);
void __cdecl ammo_mp5grenades(int param_1);
void __fastcall FUN_1004c070(int *param_1);
void * __thiscall FUN_1004c0c0(void *this,int *param_1);
void __cdecl ammo_ARgrenades(int param_1);
void FUN_1004c1a0(void);
void FUN_1004c1b0(void);
void FUN_1004c1e0(void);
void FUN_1004c220(void);
undefined4 * __fastcall FUN_1004c260(undefined4 *param_1);
void FUN_1004c320(void);
void __fastcall FUN_1004c3c0(int *param_1);
void __thiscall FUN_1004c810(void *this,int param_1);
undefined4 FUN_1004cb90(void);
void FUN_1004cbe0(int *param_1);
void __thiscall FUN_1004ccd0(void *this,void *param_1,int param_2,undefined4 param_3);
void FUN_1004cf00(int param_1,int *param_2,int *param_3);
float10 __thiscall FUN_1004d3e0(void *this,int param_1);
int __thiscall FUN_1004d650(void *this,int *param_1);
void __cdecl FUN_1004d810(int *param_1);
char * __cdecl FUN_1004d850(char *param_1);
undefined4 __thiscall FUN_1004d930(void *this,char *param_1);
undefined4 __cdecl FUN_1004d980(undefined4 param_1,undefined4 *param_2);
int FUN_1004dc10(void);
void __cdecl FUN_1004dc50(char *param_1,char *param_2);
void FUN_1004dfa0(undefined4 param_1);
void __cdecl monster_nihilanth(int param_1);
void __cdecl nihilanth_energy_ball(int param_1);
void __fastcall FUN_1004e400(int *param_1);
void __thiscall CNihilanth::NullThink(CNihilanth *this);
void __thiscall CNihilanth::StartupUse(CNihilanth *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CNihilanth::StartupThink(CNihilanth *this);
void __thiscall CNihilanth::DyingThink(CNihilanth *this);
void __thiscall CNihilanth::CrashTouch(CNihilanth *this,CBaseEntity *param_1);
void __fastcall FUN_1004f100(void *param_1);
void __fastcall FUN_1004f1f0(void *param_1);
void __fastcall FUN_1004f6d0(int param_1);
void __fastcall FUN_1004f8e0(int *param_1);
void __thiscall CNihilanth::HuntThink(CNihilanth *this);
void __fastcall FUN_100502c0(int param_1);
undefined4 __fastcall FUN_10050600(int param_1);
undefined4 __fastcall FUN_10050660(int param_1);
void __thiscall CNihilanth::CommandUse(CNihilanth *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __fastcall FUN_10051190(int *param_1);
void __thiscall FUN_10051250(void *this,int param_1);
int FUN_10051360(undefined4 param_1);
void __thiscall CNihilanthHVR::HoverThink(CNihilanthHVR *this);
void __thiscall FUN_10051470(void *this,int param_1);
void __thiscall CNihilanthHVR::ZapThink(CNihilanthHVR *this);
void __thiscall CNihilanthHVR::ZapTouch(CNihilanthHVR *this,CBaseEntity *param_1);
void __thiscall FUN_10051af0(void *this,undefined4 param_1,int param_2,int param_3,int param_4);
void __fastcall FUN_10051be0(int param_1);
void __thiscall CNihilanthHVR::TeleportThink(CNihilanthHVR *this);
void __fastcall FUN_10051f20(int param_1);
void __thiscall CNihilanthHVR::TeleportTouch(CNihilanthHVR *this,CBaseEntity *param_1);
void __thiscall CNihilanthHVR::DissipateThink(CNihilanthHVR *this);
bool __thiscall FUN_10052240(void *this,float param_1,float param_2,float param_3);
void __thiscall FUN_10052720(void *this,float param_1,float param_2,float param_3);
void __thiscall CNihilanthHVR::RemoveTouch(CNihilanthHVR *this,CBaseEntity *param_1);
void __thiscall CNihilanthHVR::BounceTouch(CNihilanthHVR *this,CBaseEntity *param_1);
void __cdecl info_node(int param_1);
void __cdecl info_node_air(int param_1);
void __fastcall FUN_10052d80(undefined4 *param_1);
undefined4 FUN_10052e10(void);
undefined4 __thiscall FUN_10052fc0(void *this,undefined4 param_1,int *param_2,uint param_3,int param_4);
undefined4 FUN_10053140(int param_1);
char FUN_100531f0(int param_1);
float10 __thiscall FUN_10053220(void *this,int param_1,int param_2,int param_3,uint param_4);
int __thiscall FUN_10053300(void *this,int param_1,int param_2,int param_3,int param_4);
int __thiscall FUN_10053390(void *this,int *param_1,int param_2,int param_3,int param_4,uint param_5);
void __thiscall FUN_100536f0(void *this,float param_1,float param_2,float param_3,int param_4);
void __cdecl FUN_10053a40(uint *param_1,uint *param_2,int param_3,uint param_4);
void __thiscall FUN_10053a90(void *this,float *param_1,int param_2);
int __thiscall FUN_10053ab0(void *this,float *param_1,uint param_2);
void __thiscall FUN_100540b0(void *this,int param_1);
int __thiscall FUN_10054220(void *this,int param_1,char **param_2,int *param_3);
int __thiscall FUN_10054650(void *this,int param_1,char **param_2);
void __cdecl testhull(int param_1);
void __fastcall FUN_10054960(int param_1);
void __thiscall CTestHull::DropDelay(CTestHull *this);
void __thiscall FUN_10054ab0(void *this,int param_1);
void __thiscall CTestHull::ShowBadNode(CTestHull *this);
void __thiscall CTestHull::CallBuildNodeGraph(CTestHull *this);
void __fastcall FUN_10054f20(int param_1);
void __thiscall CTestHull::PathFind(CTestHull *this);
void __fastcall FUN_10055f70(undefined4 *param_1);
void __thiscall FUN_10055f80(void *this,int param_1,int param_2);
int __thiscall FUN_10055fc0(void *this,int *param_1);
void __thiscall FUN_10055ff0(void *this,int param_1);
void __fastcall FUN_10056070(int *param_1);
undefined4 __thiscall FUN_100560c0(void *this,char *param_1);
undefined4 __thiscall FUN_10056490(void *this,char *param_1);
void __fastcall FUN_10056690(int param_1);
undefined4 FUN_10056760(char *param_1);
void __thiscall FUN_10056880(void *this,undefined4 param_1,undefined2 param_2,undefined2 param_3);
void __thiscall FUN_10056930(void *this,int param_1,int param_2,int *param_3);
void __thiscall FUN_10056a30(void *this,int param_1);
void __fastcall FUN_10056b30(int param_1);
void __fastcall FUN_10056d40(void *param_1);
void __fastcall FUN_10056de0(int param_1);
void __fastcall FUN_10057280(void *param_1);
void __cdecl node_viewer(int param_1);
void __cdecl node_viewer_human(int param_1);
void __cdecl node_viewer_fly(int param_1);
void __cdecl node_viewer_large(int param_1);
void __thiscall FUN_10057f40(void *this,int param_1);
void __thiscall FUN_10057fd0(void *this,int param_1,int param_2);
void __thiscall CNodeViewer::DrawThink(CNodeViewer *this);
void __thiscall FUN_10058200(void *this,char param_1);
void __fastcall FUN_10058310(void *param_1);
void __fastcall FUN_100583e0(void *param_1);
void __fastcall FUN_10058490(int param_1);
void __thiscall FUN_10058600(void *this,int param_1);
void __cdecl monster_osprey(int param_1);
void __fastcall FUN_10058850(int *param_1);
void __thiscall COsprey::CommandUse(COsprey *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall COsprey::FindAllThink(COsprey *this);
void __thiscall COsprey::DeployThink(COsprey *this);
undefined4 __fastcall FUN_100590a0(int param_1);
int * __thiscall FUN_10059120(void *this,int param_1,float param_2,float param_3);
void __thiscall COsprey::HoverThink(COsprey *this);
void __fastcall FUN_10059410(int param_1);
void __thiscall COsprey::FlyThink(COsprey *this);
void __fastcall FUN_100597a0(void *param_1);
float10 __cdecl FUN_10059cb0(float *param_1,float *param_2);
void __thiscall COsprey::HitTouch(COsprey *this,CBaseEntity *param_1);
void __thiscall COsprey::CrashTouch(COsprey *this,CBaseEntity *param_1);
void __thiscall COsprey::DyingThink(COsprey *this);
void __fastcall FUN_1005a590(int param_1);
void __cdecl path_corner(int param_1);
void __thiscall FUN_1005a940(void *this,int param_1);
void __cdecl path_track(int param_1);
void __thiscall FUN_1005aa50(void *this,int param_1);
void __thiscall FUN_1005aaa0(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __fastcall FUN_1005ab40(int param_1);
int FUN_1005acb0(int param_1,int param_2);
void FUN_1005ace0(int param_1,int param_2,float *param_3,float param_4);
int __fastcall FUN_1005add0(int param_1);
int __fastcall FUN_1005adf0(int param_1);
void __thiscall FUN_1005ae10(void *this,int param_1);
int __thiscall FUN_1005ae80(void *this,float *param_1,float param_2,int param_3);
int __thiscall FUN_1005b250(void *this,float param_1,float param_2);
undefined4 __cdecl FUN_1005b320(int param_1);
void __fastcall FUN_1005b370(int param_1);
void __thiscall FUN_1005b380(void *this,float *param_1,float *param_2);
undefined4 __thiscall FUN_1005b3c0(void *this,float *param_1);
void __thiscall FUN_1005b400(void *this,void *param_1);
void __thiscall FUN_1005b430(void *this,void *param_1);
void __thiscall FUN_1005b460(void *this,int param_1);
void __fastcall FUN_1005b5f0(int param_1);
void __thiscall CFuncPlat::CallGoDown(CFuncPlat *this);
void __thiscall CFuncPlat::CallHitTop(CFuncPlat *this);
void __thiscall CFuncPlat::CallHitBottom(CFuncPlat *this);
void __cdecl func_plat(int param_1);
void __fastcall FUN_1005b930(int param_1);
void __fastcall FUN_1005baa0(int *param_1);
void __fastcall FUN_1005bad0(int *param_1);
void __cdecl FUN_1005bb30(int param_1);
void __thiscall FUN_1005bbf0(void *this,int param_1);
void __thiscall CFuncPlat::PlatUse(CFuncPlat *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __fastcall FUN_1005be20(void *param_1);
void __fastcall FUN_1005bea0(int param_1);
void __fastcall FUN_1005bf30(void *param_1);
void __fastcall FUN_1005bfb0(int *param_1);
void __cdecl func_platrot(int param_1);
void __thiscall FUN_1005c160(void *this,void *param_1);
void __thiscall FUN_1005c190(void *this,void *param_1);
void __fastcall FUN_1005c1c0(int param_1);
void __fastcall FUN_1005c2d0(int *param_1);
void __fastcall FUN_1005c2e0(void *param_1);
void __fastcall FUN_1005c310(int param_1);
void __fastcall FUN_1005c360(void *param_1);
void __fastcall FUN_1005c390(int *param_1);
void __thiscall FUN_1005c3e0(void *this,float *param_1,float param_2);
void __cdecl func_train(int param_1);
void __thiscall FUN_1005c540(void *this,int param_1);
void __thiscall CFuncTrain::Wait(CFuncTrain *this);
void __thiscall CFuncTrain::Next(CFuncTrain *this);
void __fastcall FUN_1005cc10(int *param_1);
void __fastcall FUN_1005cd30(int *param_1);
void __cdecl func_tracktrain(int param_1);
void __thiscall FUN_1005ce90(void *this,int param_1);
void __thiscall FUN_1005cfe0(void *this,undefined4 param_1,int param_2);
void __thiscall FUN_1005d1d0(void *this,undefined4 param_1,undefined4 param_2,int param_3,float param_4);
void __fastcall FUN_1005d380(int param_1);
void __fastcall FUN_1005d410(int param_1);
void __thiscall CFuncTrackTrain::Next(CFuncTrackTrain *this);
void __cdecl FUN_1005dad0(float *param_1);
void __cdecl FUN_1005db00(float param_1);
void __thiscall CFuncTrackTrain::DeadEnd(CFuncTrackTrain *this);
void __thiscall FUN_1005dc80(void *this,int param_1);
void __thiscall CFuncTrackTrain::Find(CFuncTrackTrain *this);
void __thiscall CFuncTrackTrain::NearestPath(CFuncTrackTrain *this);
void __fastcall FUN_1005e1e0(void *param_1);
undefined4 __cdecl FUN_1005e210(int param_1);
void __fastcall FUN_1005e260(int *param_1);
void __cdecl func_traincontrols(int param_1);
void __thiscall CFuncTrainControls::Find(CFuncTrainControls *this);
void __fastcall FUN_1005e660(int param_1);
void __cdecl func_trackchange(int param_1);
void __fastcall FUN_1005e7b0(int *param_1);
void __thiscall FUN_1005e8c0(void *this,int param_1);
void __thiscall CFuncTrackChange::Find(CFuncTrackChange *this);
undefined4 __thiscall FUN_1005ec40(void *this,int param_1);
void __thiscall FUN_1005ed00(void *this,float *param_1);
void __thiscall CFuncTrackChange::GoDown(CFuncTrackChange *this);
void __thiscall CFuncTrackChange::GoUp(CFuncTrackChange *this);
void __fastcall FUN_1005f140(int *param_1);
void __fastcall FUN_1005f1c0(int *param_1);
void __cdecl func_trackautochange(int param_1);
void __fastcall FUN_1005f2a0(int param_1);
void __cdecl func_guntarget(int param_1);
void __fastcall FUN_1005f560(int param_1);
void __thiscall CGunTarget::Start(CGunTarget *this);
void __thiscall CGunTarget::Next(CGunTarget *this);
void __thiscall CGunTarget::Wait(CGunTarget *this);
undefined4 __thiscall FUN_1005f890(void *this,undefined4 param_1,undefined4 param_2,float param_3);
void __thiscall FUN_1005f920(void *this,undefined4 param_1,undefined4 param_2,int param_3);
void __fastcall FUN_1005f9a0(undefined4 *param_1);
void __fastcall FUN_1005f9b0(undefined4 *param_1);
void FUN_1005f9c0(void);
void __cdecl player(int param_1);
undefined4 __cdecl FUN_1005fe40(int param_1,int param_2);
void __thiscall FUN_1005ff80(void *this,undefined4 param_1,float param_2);
void __fastcall FUN_100605d0(void *param_1);
void __thiscall FUN_100607e0(void *this,int param_1);
void __thiscall FUN_10060920(void *this,undefined4 param_1);
void __thiscall FUN_10060b60(void *this,uint param_1);
void __fastcall FUN_10060f50(void *param_1);
void __fastcall FUN_10061020(int *param_1);
bool __fastcall FUN_10061440(int param_1);
void __thiscall CBasePlayer::PlayerDeathThink(CBasePlayer *this);
void __fastcall FUN_10061740(int param_1);
void __thiscall FUN_10061960(void *this);
void __fastcall FUN_10061bd0(int param_1);
void __thiscall FUN_10062120(void *this,int param_1,int param_2);
void __fastcall FUN_10062290(int param_1);
void __fastcall FUN_100622b0(int *param_1);
void __fastcall FUN_100629a0(int *param_1);
void __fastcall FUN_10062b30(int param_1);
void __fastcall FUN_10062be0(int param_1);
void __thiscall FUN_10062d00(void *this,byte *param_1,int param_2,int param_3);
void __fastcall FUN_10062e80(int param_1);
void __cdecl FUN_10063490(int param_1);
undefined4 __cdecl FUN_100634c0(int *param_1,int *param_2);
undefined4 __cdecl FUN_10063530(int *param_1);
void __fastcall FUN_10063840(int *param_1);
void __thiscall FUN_10063f80(void *this,int **param_1);
void __fastcall FUN_10064090(int param_1);
undefined4 __fastcall FUN_10064100(int param_1);
void __thiscall FUN_10064150(void *this,int param_1);
void __thiscall FUN_10064350(void *this,int param_1);
void __thiscall FUN_100644a0(void *this,int param_1);
undefined4 FUN_10064540(int param_1);
uint __fastcall FUN_10064660(int param_1);
void __fastcall FUN_10064670(int param_1);
void __fastcall FUN_10064720(int param_1);
void __fastcall FUN_100647b0(int *param_1);
void __thiscall FUN_10064a70(void *this,undefined4 param_1);
void __fastcall FUN_10065520(int param_1);
void __fastcall FUN_10065550(int *param_1);
undefined4 __thiscall FUN_100655a0(void *this,int param_1);
int __thiscall FUN_100655c0(void *this,byte *param_1);
void __fastcall FUN_10065600(int param_1);
void __thiscall FUN_10065ca0(void *this,undefined4 param_1);
int __fastcall FUN_10065d80(int param_1);
void __thiscall FUN_10065db0(void *this,int param_1);
void __thiscall FUN_10065de0(void *this,undefined4 *param_1);
void __thiscall FUN_10066150(void *this,float *param_1,float *param_2,float param_3,float param_4);
void __fastcall FUN_100666c0(int param_1);
void __thiscall FUN_10066750(void *this,int param_1);
undefined4 __fastcall FUN_10066780(int param_1);
void __thiscall FUN_10066790(void *this,byte *param_1);
undefined4 __thiscall FUN_10066a80(void *this,int *param_1);
undefined4 __thiscall FUN_10066b10(void *this,byte *param_1);
undefined4 __thiscall FUN_10066bb0(void *this,int *param_1);
void __thiscall FUN_10066c00(void *this,int param_1);
void __cdecl monster_hevsuit_dead(int param_1);
void __cdecl player_weaponstrip(int param_1);
void FUN_10066dd0(int *param_1);
void __cdecl player_loadsaved(int param_1);
void __thiscall FUN_10066ee0(void *this,int param_1);
void __fastcall FUN_10066fd0(int param_1);
void __thiscall CRevertSaved::MessageThink(CRevertSaved *this);
void __thiscall CRevertSaved::LoadThink(CRevertSaved *this);
void __fastcall FUN_100670c0(int param_1);
void __cdecl info_intermission(int param_1);
void __cdecl FUN_100672a0(float *param_1,float *param_2,undefined4 param_3,undefined4 param_4);
void __cdecl FUN_10067370(float *param_1,float *param_2,float *param_3,float *param_4,undefined4 param_5,undefined4 param_6);
void __cdecl FUN_100673d0(int param_1,undefined4 param_2,undefined4 param_3);
void __cdecl FUN_10067850(float *param_1,float *param_2,float *param_3,float *param_4);
void __cdecl FUN_10067950(float *param_1,float *param_2,float *param_3,float *param_4);
void __cdecl FUN_10067bf0(int param_1);
void __cdecl FUN_10067c40(int param_1,float *param_2,int param_3,float param_4);
undefined4 __cdecl FUN_10067db0(int param_1,float *param_2);
void __cdecl FUN_10067de0(float *param_1,float param_2,float *param_3,float *param_4);
void __cdecl FUN_10067ec0(float *param_1,float *param_2,float *param_3);
float10 __cdecl FUN_10067f00(int param_1);
void __cdecl FUN_10067f60(float *param_1);
void __cdecl FUN_10067fd0(float *param_1,float param_2,float *param_3);
void __cdecl FUN_10068190(int param_1,int param_2);
void __fastcall FUN_10068210(void *param_1);
void FUN_10068280(void);
undefined __cdecl FUN_10068510(byte *param_1);
void __cdecl FUN_10068570(undefined4 param_1,undefined4 param_2);
undefined4 __cdecl FUN_10068cf0(undefined param_1);
void FUN_10068d70(void);
void FUN_10068e50(void);
undefined4 FUN_10069160(undefined param_1,undefined param_2,undefined param_3,undefined param_4,undefined param_5,undefined param_6,undefined param_7,undefined param_8,undefined param_9,undefined param_10,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,undefined4 *param_15);
void FUN_10069200(void);
byte __cdecl FUN_100692f0(float *param_1,float *param_2,float *param_3,float param_4);
void FUN_100693a0(void);
void FUN_10069420(void);
uint FUN_10069480(void);
void __cdecl FUN_10069920(float *param_1,float param_2,float param_3);
void FUN_100699c0(void);
void FUN_10069ee0(void);
void __cdecl FUN_1006a080(float *param_1,float param_2,float param_3);
void FUN_1006a140(void);
void FUN_1006a450(void);
bool FUN_1006a590(void);
bool FUN_1006a5b0(void);
void FUN_1006a770(void);
void __cdecl FUN_1006a8b0(int param_1,int param_2,undefined4 *param_3);
void __cdecl FUN_1006a900(int param_1,int param_2);
undefined4 FUN_1006a920(void);
void FUN_1006ac20(void);
float10 __cdecl FUN_1006af20(float param_1,float param_2);
void __cdecl FUN_1006af40(int param_1);
void FUN_1006afe0(void);
void FUN_1006b140(void);
void __cdecl FUN_1006b380(int param_1);
int FUN_1006b740(void);
void FUN_1006b810(void);
void FUN_1006b8d0(void);
void __cdecl FUN_1006b930(int *param_1,float *param_2);
void FUN_1006ba10(void);
void FUN_1006bd10(void);
void FUN_1006bdc0(void);
void FUN_1006be30(void);
void FUN_1006c190(void);
void FUN_1006c400(void);
void FUN_1006c5c0(void);
float10 __cdecl FUN_1006c6b0(float *param_1,float *param_2,float param_3,float param_4);
void __cdecl FUN_1006c740(float *param_1);
void FUN_1006c790(void);
void FUN_1006c9c0(void);
void __cdecl FUN_1006cac0(undefined4 param_1);
void FUN_1006cee0(void);
void __cdecl weapon_python(int param_1);
void __cdecl weapon_357(int param_1);
void __fastcall FUN_1006d350(int *param_1);
void __fastcall FUN_1006d430(int *param_1);
void __fastcall FUN_1006d490(int *param_1);
void __fastcall FUN_1006d500(int param_1);
void __fastcall FUN_1006d770(void *param_1);
void __cdecl ammo_357(int param_1);
void __fastcall FUN_1006d910(int *param_1);
undefined4 __thiscall FUN_1006d960(void *this,int *param_1);
void __cdecl monster_rat(int param_1);
void __cdecl monster_cockroach(int param_1);
void __thiscall CRoach::Touch(CRoach *this,CBaseEntity *param_1);
void __fastcall FUN_1006de30(int param_1);
void __thiscall CRoach::MonsterThink(CRoach *this);
void __thiscall FUN_1006e1e0(void *this,int param_1);
void __cdecl weapon_rpg(int param_1);
void __cdecl laser_spot(int param_1);
undefined4 * FUN_1006e700(void);
void __fastcall FUN_1006e770(int *param_1);
void __thiscall FUN_1006e7e0(void *this,float param_1);
void __thiscall CLaserSpot::Revive(CLaserSpot *this);
void __cdecl rpg_rocket(int param_1);
undefined4 * FUN_1006e890(void);
void __fastcall FUN_1006e950(int *param_1);
void __thiscall CRpgRocket::RocketTouch(CRpgRocket *this,CBaseEntity *param_1);
void __thiscall CRpgRocket::IgniteThink(CRpgRocket *this);
void __thiscall CRpgRocket::FollowThink(CRpgRocket *this);
void __fastcall FUN_1006f2f0(int *param_1);
void __fastcall FUN_1006f510(int *param_1);
void __fastcall FUN_1006f7e0(int param_1);
void __fastcall FUN_1006f830(int *param_1);
void __fastcall FUN_1006f910(int param_1);
void __cdecl ammo_rpgclip(int param_1);
void __fastcall FUN_1006fa40(int *param_1);
undefined4 __thiscall FUN_1006fa90(void *this,int *param_1);
void __cdecl monster_satchel(int param_1);
void __fastcall FUN_1006fb90(int param_1);
void __thiscall CSatchelCharge::SatchelSlide(CSatchelCharge *this,CBaseEntity *param_1);
void __thiscall CSatchelCharge::SatchelThink(CSatchelCharge *this);
void __cdecl weapon_satchel(int param_1);
undefined4 __thiscall FUN_10070040(void *this,int param_1);
void __fastcall FUN_100700c0(int *param_1);
bool __fastcall FUN_100701c0(int *param_1);
bool __fastcall FUN_100701f0(int *param_1);
void __fastcall FUN_100702b0(int *param_1);
void __cdecl FUN_10070780(int param_1);
void __fastcall FUN_10070820(int param_1);
bool __fastcall FUN_10070840(int param_1);
void __thiscall FUN_10070860(void *this,int param_1);
void __fastcall FUN_100708d0(int param_1);
uint __fastcall FUN_10070900(int param_1);
uint __fastcall FUN_10070920(int param_1);
void __fastcall FUN_10070950(int *param_1);
void __thiscall FUN_10070b20(void *this,int *param_1);
void __fastcall FUN_10071130(void *param_1);
void __thiscall FUN_100711a0(void *this,int *param_1);
int __fastcall FUN_10072390(int param_1);
undefined ** __fastcall FUN_100723b0(int *param_1);
void __cdecl monster_scientist(int param_1);
void __thiscall FUN_10072700(void *this,void *param_1);
void __thiscall FUN_10072730(void *this,void *param_1);
void __fastcall FUN_100727e0(int *param_1);
void __thiscall FUN_10072870(void *this,int *param_1);
void __fastcall FUN_10072e70(int *param_1);
int __fastcall FUN_10073010(int param_1);
undefined ** __fastcall FUN_10073450(int *param_1);
int __fastcall FUN_100736c0(int *param_1);
undefined4 __fastcall FUN_10073840(int param_1);
void __fastcall FUN_100738c0(int param_1);
void __thiscall FUN_10073970(void *this,int param_1);
void __cdecl monster_scientist_dead(int param_1);
void __cdecl monster_sitting_scientist(int param_1);
void __fastcall FUN_10073bc0(int *param_1);
void __thiscall CSittingScientist::SittingThink(CSittingScientist *this);
undefined4 __fastcall FUN_100740d0(int *param_1);
void __thiscall FUN_10074290(void *this,int param_1);
void __cdecl scripted_sequence(int param_1);
void __cdecl aiscripted_sequence(int param_1);
void __fastcall FUN_100745c0(int param_1);
undefined4 __fastcall FUN_10074660(int *param_1);
void __thiscall CCineMonster::CineThink(CCineMonster *this);
undefined4 __thiscall FUN_10074d90(void *this,int *param_1,int param_2,int param_3);
undefined4 __thiscall FUN_10074e40(void *this,int *param_1,int param_2,int param_3);
void __thiscall FUN_10074ef0(void *this,int *param_1);
undefined4 __fastcall FUN_10074fc0(int param_1);
void __thiscall FUN_10074ff0(void *this,undefined4 param_1);
undefined4 __fastcall FUN_10075010(int param_1);
void __cdecl FUN_10075060(int param_1);
void __fastcall FUN_10075130(int param_1);
void __thiscall FUN_100751e0(void *this,int param_1);
undefined4 __fastcall FUN_10075450(int *param_1);
void __cdecl scripted_sentence(int param_1);
void __thiscall FUN_10075820(void *this,int param_1);
void __thiscall CScriptedSentence::FindThink(CScriptedSentence *this);
void __thiscall CScriptedSentence::DelayThink(CScriptedSentence *this);
undefined4 __thiscall FUN_10075b80(void *this,int *param_1);
int * __fastcall FUN_10075c10(void *param_1);
undefined4 __thiscall FUN_10075d50(void *this,int *param_1);
void __cdecl monster_furniture(int param_1);
void __fastcall FUN_10075f00(int *param_1);
void __cdecl weapon_shotgun(int param_1);
void __fastcall FUN_10076030(int *param_1);
void __fastcall FUN_100766b0(int *param_1);
void __fastcall FUN_100769f0(int *param_1);
void __cdecl ammo_buckshot(int param_1);
void __fastcall FUN_10076ac0(int *param_1);
undefined4 __thiscall FUN_10076b10(void *this,int *param_1);
undefined4 * __fastcall FUN_10076b80(undefined4 *param_1);
float10 __cdecl FUN_10076f30(undefined4 param_1);
void __cdecl ambient_generic(int param_1);
void __fastcall FUN_10077050(int *param_1);
void __fastcall FUN_10077150(int param_1);
void __thiscall CAmbientGeneric::RampThink(CAmbientGeneric *this);
void __fastcall FUN_100775b0(int param_1);
void __thiscall CAmbientGeneric::ToggleUse(CAmbientGeneric *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl env_sound(int param_1);
void __thiscall FUN_10077f20(void *this,int param_1);
undefined4 __cdecl FUN_10077f90(int param_1,int param_2,float *param_3);
void __cdecl FUN_10078300(int param_1,int param_2);
uint __cdecl FUN_10078370(uint param_1,char *param_2,int param_3,int param_4);
uint __cdecl FUN_10078480(uint param_1,char *param_2);
int __cdecl FUN_100785a0(byte *param_1);
uint __cdecl FUN_10078620(void *param_1,uint param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6);
uint __cdecl FUN_10078680(void *param_1,byte *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6);
uint __cdecl FUN_10078710(void *param_1,byte *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,int param_7,int param_8);
void FUN_10078880(void);
int __thiscall FUN_10078b50(void *this,int param_1,char *param_2);
void __thiscall FUN_10078c00(void *this,undefined4 param_1,undefined4 param_2,char *param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7);
void __cdecl FUN_10078c90(undefined4 param_1,void *param_2);
void __cdecl FUN_10078d00(void *param_1,uint param_2);
void __cdecl FUN_10078d70(void *param_1,byte *param_2);
undefined4 * __cdecl FUN_10078de0(int param_1,int param_2,int *param_3,undefined4 *param_4,int param_5);
void FUN_10078e80(void);
undefined __cdecl FUN_10079060(byte *param_1);
float10 __cdecl FUN_100790b0(int param_1,float param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,float param_8);
void __cdecl speaker(int param_1);
void __fastcall FUN_10079650(int *param_1);
void __fastcall FUN_10079710(int param_1);
void __thiscall CSpeaker::SpeakerThink(CSpeaker *this);
void __thiscall CSpeaker::ToggleUse(CSpeaker *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall FUN_10079980(void *this,int param_1);
void __cdecl soundent(int param_1);
void __fastcall FUN_10079a20(undefined4 *param_1);
void __fastcall FUN_10079a60(undefined4 *param_1);
bool __fastcall FUN_10079a90(int param_1);
bool __fastcall FUN_10079aa0(int param_1);
void __fastcall FUN_10079ab0(int param_1);
void __cdecl FUN_10079ba0(int param_1,int param_2);
int __fastcall FUN_10079bf0(int param_1);
void __cdecl FUN_10079c30(undefined4 param_1,undefined4 *param_2,undefined4 param_3,float param_4);
void __fastcall FUN_10079cb0(int param_1);
int __thiscall FUN_10079d70(void *this,int param_1);
undefined4 FUN_10079dc0(void);
int __cdecl FUN_10079e00(int param_1);
int __cdecl FUN_10079e50(undefined4 param_1);
void __fastcall FUN_10079e70(int param_1);
void __fastcall FUN_10079eb0(int param_1);
void __fastcall FUN_10079f90(int param_1);
void __thiscall FUN_1007a010(void *this,void *param_1);
void __thiscall FUN_1007a040(void *this,void *param_1);
undefined4 __thiscall FUN_1007a070(void *this,uint param_1);
void __fastcall FUN_1007a110(int param_1);
void __thiscall FUN_1007a170(void *this,undefined4 param_1,int param_2);
void __thiscall FUN_1007a1c0(void *this,int param_1);
undefined4 __thiscall FUN_1007a280(void *this,int param_1);
void __fastcall FUN_1007a2e0(int param_1);
void __fastcall FUN_1007a320(int param_1);
void __thiscall FUN_1007a360(void *this,void *param_1);
int __fastcall FUN_1007a470(int param_1);
int __thiscall FUN_1007a4d0(void *this,int param_1,int param_2);
int __fastcall FUN_1007a790(void *param_1);
void __fastcall FUN_1007a810(int *param_1);
undefined4 __fastcall FUN_1007a8e0(int param_1);
void __fastcall FUN_1007ab70(int *param_1);
bool __thiscall FUN_1007abc0(void *this,float *param_1);
undefined4 __fastcall FUN_1007ac00(int param_1);
undefined4 __thiscall FUN_1007ac90(void *this,float *param_1,float param_2);
undefined ** __thiscall FUN_1007ad20(void *this,int param_1);
void __cdecl monster_snark(int param_1);
int __fastcall FUN_1007ae20(int param_1);
void __thiscall FUN_1007b070(void *this,undefined4 param_1);
void __thiscall CSqueakGrenade::HuntThink(CSqueakGrenade *this);
void __thiscall CSqueakGrenade::SuperBounceTouch(CSqueakGrenade *this,CBaseEntity *param_1);
void __cdecl weapon_snark(int param_1);
void __fastcall FUN_1007bb10(int *param_1);
void __fastcall FUN_1007bce0(int *param_1);
void __cdecl info_null(int param_1);
void __cdecl info_player_deathmatch(int param_1);
void __cdecl info_player_start(int param_1);
void __cdecl info_landmark(int param_1);
void __thiscall FUN_1007c320(void *this,int param_1);
void __fastcall FUN_1007c390(int param_1);
void __thiscall CBaseEntity::SUB_Remove(CBaseEntity *this);
void __thiscall CBaseEntity::SUB_DoNothing(CBaseEntity *this);
void __thiscall FUN_1007c460(void *this,void *param_1);
void __thiscall FUN_1007c490(void *this,void *param_1);
void __thiscall FUN_1007c4c0(void *this,int param_1);
void __thiscall FUN_1007c540(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3);
void __cdecl FUN_1007c580(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
void __cdecl DelayedUse(int inputParam);
void __thiscall FUN_1007c680(void *this,int *param_1,undefined4 param_2,undefined4 param_3);
void __cdecl FUN_1007c880(int param_1);
void __thiscall CBaseDelay::DelayThink(CBaseDelay *this);
void __thiscall FUN_1007c9d0(void *this,void *param_1);
void __thiscall FUN_1007ca00(void *this,void *param_1);
void __thiscall FUN_1007ca30(void *this,int param_1);
void __thiscall FUN_1007cb10(void *this,float param_1,float param_2,float param_3,float param_4);
void __thiscall CBaseToggle::LinearMoveDone(CBaseToggle *this);
undefined4 __fastcall FUN_1007ccb0(int param_1);
void __thiscall FUN_1007ccf0(void *this,float param_1,float param_2,float param_3,float param_4);
void __thiscall CBaseToggle::AngularMoveDone(CBaseToggle *this);
void __cdecl FUN_1007ce70(int param_1);
float10 __cdecl FUN_1007cf00(byte param_1,float *param_2,float *param_3);
void __thiscall FUN_1007cff0(void *this,void *param_1);
void __thiscall FUN_1007d020(void *this,void *param_1);
void __thiscall FUN_1007d050(void *this,byte *param_1);
void __thiscall FUN_1007d080(void *this,int param_1);
void __thiscall FUN_1007d0d0(void *this,int *param_1);
void __thiscall FUN_1007d4c0(void *this,int *param_1);
void __thiscall FUN_1007d850(void *this,int param_1,int param_2);
int * __thiscall FUN_1007d8d0(void *this,undefined4 param_1,int param_2);
void __fastcall FUN_1007d9c0(void *param_1);
void __fastcall FUN_1007da20(void *param_1);
void __thiscall FUN_1007da70(void *this,int param_1,int param_2);
float10 __fastcall FUN_1007daf0(int param_1);
void __thiscall FUN_1007db70(void *this,int *param_1);
void __fastcall FUN_1007dbe0(int param_1);
int * __thiscall FUN_1007dc00(void *this,int param_1);
int __fastcall FUN_1007de20(int param_1);
void __fastcall FUN_1007dec0(int *param_1);
undefined4 __fastcall FUN_1007df00(int *param_1);
undefined4 __fastcall FUN_1007dfe0(int *param_1);
undefined4 __fastcall FUN_1007e040(int *param_1);
void __thiscall FUN_1007e110(void *this,float *param_1);
undefined4 __fastcall FUN_1007e1b0(int *param_1);
void __thiscall FUN_1007e5f0(void *this,float param_1);
void __thiscall FUN_1007e630(void *this,int param_1);
void __thiscall FUN_1007e660(void *this,int param_1,int param_2,float param_3,uint param_4);
undefined ** __thiscall FUN_1007e6e0(void *this,undefined4 param_1);
undefined4 __fastcall FUN_1007e9a0(int param_1);
void __fastcall FUN_1007e9e0(int *param_1);
undefined4 __thiscall FUN_1007ea90(void *this,int *param_1);
void __thiscall FUN_1007ead0(void *this,int param_1);
void __thiscall FUN_1007eba0(void *this,int param_1);
undefined4 __fastcall FUN_1007ec40(int *param_1);
void __thiscall CTalkMonster::FollowerUse(CTalkMonster *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall FUN_1007ed60(void *this,int param_1);
void __fastcall FUN_1007edf0(int param_1);
undefined4 * __fastcall FUN_1007ee30(undefined4 *param_1);
char * __thiscall FUN_1007f140(void *this,int param_1);
void __thiscall FUN_1007f400(void *this,int *param_1,char *param_2,int param_3,int param_4);
void __thiscall FUN_1007f870(void *this,void *param_1,int param_2,undefined4 param_3);
undefined4 __thiscall FUN_1007f8b0(void *this,int param_1,int param_2);
undefined4 __thiscall FUN_1007f900(void *this,byte *param_1,int *param_2);
int __thiscall FUN_1007fa50(void *this,byte *param_1);
undefined4 * __fastcall FUN_1007fb00(int *param_1);
void __thiscall FUN_1007fbb0(void *this,char param_1);
void __cdecl monster_tentacle(int param_1);
void __fastcall FUN_10080110(undefined4 *param_1);
void __thiscall FUN_10080200(void *this,int param_1);
undefined4 FUN_10080290(float param_1);
float10 __fastcall FUN_100802e0(int param_1);
undefined4 __fastcall FUN_10080310(int param_1);
void __thiscall CTentacle::Test(CTentacle *this);
void __thiscall CTentacle::Cycle(CTentacle *this);
void __thiscall CTentacle::CommandUse(CTentacle *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CTentacle::DieThink(CTentacle *this);
void __thiscall CTentacle::Start(CTentacle *this);
void __thiscall CTentacle::HitTouch(CTentacle *this,CBaseEntity *param_1);
void __cdecl monster_tentaclemaw(int param_1);
void __cdecl func_friction(int param_1);
void __fastcall FUN_100816c0(int param_1);
void __thiscall CFrictionModifier::ChangeFriction(CFrictionModifier *this,CBaseEntity *param_1);
void __thiscall FUN_10081740(void *this,int param_1);
void __cdecl trigger_auto(int param_1);
void __thiscall FUN_10081850(void *this,int param_1);
void __fastcall FUN_10081930(void *param_1);
void __cdecl trigger_relay(int param_1);
void __thiscall FUN_10081a30(void *this,int param_1);
void __fastcall FUN_10081ac0(void *param_1);
void __cdecl multi_manager(int param_1);
void __thiscall CMultiManager::ManagerThink(CMultiManager *this);
void __fastcall FUN_10081e50(int param_1);
void __thiscall CMultiManager::ManagerUse(CMultiManager *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl env_render(int param_1);
void __fastcall FUN_10081fe0(int param_1);
void __cdecl trigger(int param_1);
void __fastcall FUN_10082120(int param_1);
void __thiscall FUN_100821d0(void *this,int param_1);
void __cdecl trigger_hurt(int param_1);
void __cdecl trigger_monsterjump(int param_1);
void __fastcall FUN_10082330(int param_1);
void __fastcall FUN_100823a0(int param_1);
void __cdecl trigger_cdaudio(int param_1);
void __thiscall FUN_100824b0(void *this,int *param_1);
void __cdecl FUN_100824f0(int param_1);
void __fastcall FUN_10082570(int param_1);
void __cdecl target_cdaudio(int param_1);
void __thiscall FUN_100825f0(void *this,int param_1);
void __fastcall FUN_10082710(int param_1);
void __fastcall FUN_10082740(int param_1);
void __thiscall CTriggerHurt::RadiationThink(CTriggerHurt *this);
void __thiscall CBaseTrigger::ToggleUse(CBaseTrigger *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CBaseTrigger::HurtTouch(CBaseTrigger *this,CBaseEntity *param_1);
void __cdecl trigger_multiple(int param_1);
void __fastcall FUN_10082d30(int param_1);
void __cdecl trigger_once(int param_1);
void __thiscall CBaseTrigger::MultiTouch(CBaseTrigger *this,CBaseEntity *param_1);
float * __thiscall FUN_10082e30(void *this,int *param_1);
void __thiscall CBaseTrigger::MultiWaitOver(CBaseTrigger *this);
void __thiscall CBaseTrigger::CounterUse(CBaseTrigger *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __cdecl trigger_counter(int param_1);
void __cdecl trigger_transition(int param_1);
void __fastcall FUN_100831d0(int param_1);
void __cdecl fireanddie(int param_1);
void __fastcall FUN_100832d0(void *param_1);
void __cdecl trigger_changelevel(int param_1);
void __thiscall FUN_100833a0(void *this,int param_1);
void __thiscall CChangeLevel::ExecuteChangeLevel(CChangeLevel *this);
int __cdecl FUN_10083600(undefined4 param_1);
void __thiscall CChangeLevel::UseChangeLevel(CChangeLevel *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall FUN_10083690(void *this,int *param_1);
void __thiscall CChangeLevel::TouchChangeLevel(CChangeLevel *this,CBaseEntity *param_1);
undefined4 __cdecl FUN_100838b0(byte *param_1,int param_2,byte *param_3,char *param_4,int param_5);
int thunk_FUN_10083a60(void);
undefined4 __cdecl FUN_100839a0(int *param_1,undefined4 param_2);
int FUN_10083a60(void);
void __cdecl func_ladder(int param_1);
void __fastcall FUN_10083e80(int param_1);
void __fastcall FUN_10083ef0(int *param_1);
void __cdecl trigger_push(int param_1);
void __fastcall FUN_10083fa0(int param_1);
void __thiscall CBaseTrigger::TeleportTouch(CBaseTrigger *this,CBaseEntity *param_1);
void __cdecl trigger_teleport(int param_1);
void __fastcall FUN_10084390(int param_1);
void __cdecl info_teleport_destination(int param_1);
void __cdecl trigger_autosave(int param_1);
void __fastcall FUN_10084450(int param_1);
void __thiscall CTriggerSave::SaveTouch(CTriggerSave *this,CBaseEntity *param_1);
void __cdecl trigger_endsection(int param_1);
void __thiscall CTriggerEndSection::EndSectionUse(CTriggerEndSection *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __fastcall FUN_10084580(int param_1);
void __thiscall CTriggerEndSection::EndSectionTouch(CTriggerEndSection *this,CBaseEntity *param_1);
void __thiscall FUN_10084620(void *this,int param_1);
void __cdecl trigger_gravity(int param_1);
void __fastcall FUN_100846c0(int param_1);
void __thiscall CTriggerGravity::GravityTouch(CTriggerGravity *this,CBaseEntity *param_1);
void __cdecl trigger_changetarget(int param_1);
void __thiscall FUN_100847d0(void *this,int param_1);
void __cdecl trigger_camera(int param_1);
void __thiscall FUN_100849c0(void *this,int param_1);
void __thiscall CTriggerCamera::FollowTarget(CTriggerCamera *this);
void __fastcall FUN_10085020(int param_1);
void __cdecl monster_tripmine(int param_1);
void __fastcall FUN_100853b0(int *param_1);
void __thiscall CTripmineGrenade::WarningThink(CTripmineGrenade *this);
void __thiscall CTripmineGrenade::PowerupThink(CTripmineGrenade *this);
void __fastcall FUN_10085a60(int param_1);
void __fastcall FUN_10085a90(int param_1);
void __thiscall CTripmineGrenade::BeamBreakThink(CTripmineGrenade *this);
void __thiscall FUN_10085dc0(void *this,int param_1);
void __thiscall CTripmineGrenade::DelayDeathThink(CTripmineGrenade *this);
void __cdecl weapon_tripmine(int param_1);
void __fastcall FUN_10086120(int *param_1);
void __fastcall FUN_10086420(int *param_1);
void __thiscall CBaseTurret::SpinDownCall(CBaseTurret *this);
void __thiscall CBaseTurret::SpinUpCall(CBaseTurret *this);
void __thiscall FUN_100865d0(void *this,void *param_1);
void __thiscall FUN_10086600(void *this,void *param_1);
void __cdecl monster_turret(int param_1);
void __cdecl monster_miniturret(int param_1);
void __thiscall FUN_10086790(void *this,int param_1);
void __fastcall FUN_100868f0(int *param_1);
void FUN_100869c0(void);
void __thiscall CBaseTurret::Initialize(CBaseTurret *this);
void __thiscall CBaseTurret::TurretUse(CBaseTurret *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __fastcall FUN_10086f40(int *param_1);
void __thiscall CBaseTurret::ActiveThink(CBaseTurret *this);
void __thiscall CBaseTurret::Deploy(CBaseTurret *this);
void __thiscall CBaseTurret::Retire(CBaseTurret *this);
void __fastcall FUN_10087ad0(void *param_1);
void __thiscall FUN_10087b90(void *this,int param_1);
void __thiscall CBaseTurret::SearchThink(CBaseTurret *this);
void __thiscall CBaseTurret::AutoSearchThink(CBaseTurret *this);
void __thiscall CBaseTurret::TurretDeath(CBaseTurret *this);
undefined4 __thiscall FUN_10088230(void *this,undefined4 param_1,undefined4 param_2,float param_3);
int __fastcall FUN_10088330(void *param_1);
void __cdecl monster_sentry(int param_1);
undefined4 __thiscall FUN_10088880(void *this,undefined4 param_1,undefined4 param_2,float param_3);
void __thiscall CSentry::SentryTouch(CSentry *this,CBaseEntity *param_1);
void __thiscall CSentry::SentryDeath(CSentry *this);
float10 FUN_10088c40(void);
uint FUN_10088c50(void);
void __cdecl FUN_10088c90(uint param_1);
float10 __cdecl FUN_10088cf0(int param_1,float param_2,int param_3);
void FUN_10088ed0(undefined4 param_1,undefined4 param_2);
void FUN_10088f00(void);
float10 __cdecl FUN_10088fa0(float param_1);
float10 __cdecl FUN_10089020(float param_1,float param_2);
void __cdecl FUN_10089070(undefined4 *param_1,undefined4 param_2);
void __cdecl FUN_100890a0(undefined4 param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4);
int __cdecl FUN_100890e0(int param_1,int param_2,float *param_3,float *param_4,uint param_5);
int __cdecl FUN_100891e0(int param_1,int param_2,float *param_3,float param_4);
undefined4 __cdecl FUN_100892e0(int param_1,undefined4 param_2,undefined4 param_3);
undefined4 __cdecl FUN_10089330(int param_1,undefined4 param_2,undefined4 param_3);
void __cdecl FUN_10089380(int param_1,undefined4 param_2);
void __cdecl FUN_100893a0(int param_1,undefined4 param_2);
int __cdecl FUN_100893c0(undefined4 param_1,float *param_2,float param_3);
int __cdecl FUN_10089460(int param_1);
void FUN_100894a0(void);
void __cdecl FUN_100894b0(float *param_1);
void __cdecl FUN_100894e0(undefined4 param_1,int param_2);
void __cdecl FUN_10089560(undefined4 param_1,undefined4 *param_2,char *param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7);
void __cdecl FUN_10089600(float *param_1,float param_2,undefined4 param_3,int param_4,float param_5);
int FUN_10089770(undefined4 param_1,undefined4 param_2);
void __cdecl FUN_100897c0(undefined2 *param_1);
void __cdecl FUN_10089830(undefined2 *param_1,int *param_2);
void FUN_100898d0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
void __cdecl FUN_10089940(int *param_1);
void __cdecl FUN_10089980(int *param_1,undefined4 *param_2,char *param_3);
int FUN_10089b60(undefined4 param_1,undefined4 param_2);
void __cdecl FUN_10089b90(undefined4 *param_1,char *param_2);
void FUN_10089be0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,int param_6);
void FUN_10089c60(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5,int param_6,int param_7);
void __cdecl FUN_10089cf0(undefined4 param_1,int *param_2);
void FUN_10089d50(undefined4 param_1,int param_2);
undefined * FUN_10089da0(undefined4 param_1);
void __cdecl FUN_10089e20(undefined4 param_1,int *param_2);
void __cdecl FUN_10089e70(undefined4 param_1);
void __cdecl FUN_10089ec0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,undefined4 param_6);
void FUN_10089f00(undefined param_1,undefined param_2,undefined4 param_3);
void FUN_10089f20(undefined param_1,undefined param_2,undefined4 param_3);
void FUN_10089f40(void);
void __cdecl FUN_10089f50(undefined4 *param_1);
void FUN_1008a020(undefined4 param_1);
void FUN_1008a040(void);
void __cdecl FUN_1008a050(int param_1);
void __cdecl FUN_1008a070(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4);
float10 __cdecl FUN_1008a0c0(float param_1,float param_2,float param_3);
float10 __cdecl FUN_1008a100(float param_1,undefined4 param_2,float param_3);
float10 __cdecl FUN_1008a1a0(float param_1,float param_2);
float10 __cdecl FUN_1008a1e0(float param_1,float param_2);
undefined * __cdecl FUN_1008a200(byte *param_1);
undefined4 __cdecl FUN_1008a260(int param_1,undefined4 param_2);
undefined4 __cdecl FUN_1008a2e0(int param_1);
void FUN_1008a340(void);
void __cdecl FUN_1008a350(undefined4 *param_1,undefined4 *param_2,int param_3,int param_4);
void __cdecl FUN_1008a400(undefined4 *param_1,undefined4 param_2,int param_3,int param_4);
void __cdecl FUN_1008a500(float *param_1);
void __cdecl FUN_1008a550(int param_1,int param_2);
void __cdecl FUN_1008a5a0(int param_1,int param_2);
void __cdecl FUN_1008a6a0(int param_1,undefined4 param_2,int param_3,int param_4);
void __cdecl FUN_1008a740(int param_1,int param_2);
void FUN_1008a7d0(undefined4 *param_1);
void FUN_1008a820(undefined4 *param_1);
undefined4 __cdecl FUN_1008a880(char *param_1,byte *param_2);
void __cdecl FUN_1008a8c0(int param_1,char *param_2);
void __cdecl FUN_1008a950(int param_1,int param_2,char *param_3);
void __cdecl FUN_1008a9e0(float *param_1,float *param_2,float *param_3);
float10 __cdecl FUN_1008ab20(undefined4 param_1,float param_2,float param_3);
void FUN_1008abf0(float param_1,float param_2,float param_3,float param_4,float param_5,float param_6,undefined4 param_7);
void __cdecl FUN_1008acf0(undefined4 param_1,undefined4 param_2,float param_3,undefined4 param_4,undefined4 param_5,float param_6,int param_7);
void __cdecl FUN_1008ae10(int param_1);
undefined4 __cdecl FUN_1008ae50(int *param_1);
void __cdecl FUN_1008ae80(int param_1);
void __cdecl FUN_1008af00(byte *param_1);
float10 __cdecl FUN_1008af30(float *param_1,float *param_2,float *param_3);
void __cdecl FUN_1008afb0(char *param_1,undefined *param_2);
void __thiscall FUN_1008b000(void *this,undefined4 param_1);
void FUN_1008b010(void);
int __thiscall FUN_1008b020(void *this,int param_1);
int __thiscall FUN_1008b040(void *this,int param_1);
void __thiscall FUN_1008b060(void *this,undefined4 param_1);
int __thiscall FUN_1008b080(void *this,int param_1);
int __thiscall FUN_1008b0c0(void *this,int param_1);
undefined4 __thiscall FUN_1008b100(void *this,int param_1,uint param_2);
void __thiscall FUN_1008b150(void *this,int param_1);
uint FUN_1008b180(char *param_1);
uint __thiscall FUN_1008b1a0(void *this,byte *param_1);
void __thiscall thunk_FUN_1008ba60(void *this,byte *param_1,uint param_2,undefined4 *param_3);
void __thiscall FUN_1008b2d0(void *this,byte *param_1,undefined4 *param_2,int param_3);
void __thiscall FUN_1008b2f0(void *this,byte *param_1,undefined4 *param_2,int param_3);
void __thiscall FUN_1008b310(void *this,byte *param_1,float *param_2,float param_3);
void __thiscall FUN_1008b370(void *this,byte *param_1,undefined4 *param_2);
void __thiscall FUN_1008b3a0(void *this,byte *param_1,int param_2,int param_3);
void __thiscall FUN_1008b430(void *this,byte *param_1,undefined4 *param_2);
void __thiscall FUN_1008b450(void *this,byte *param_1,undefined4 *param_2,int param_3);
void __thiscall FUN_1008b4f0(void *this,byte *param_1,float *param_2,int param_3);
void __thiscall FUN_1008b5a0(void *this,byte *param_1,undefined4 *param_2);
void __cdecl FUN_1008b5f0(int param_1,int param_2);
void __thiscall FUN_1008b710(void *this,byte *param_1,int param_2);
undefined4 __thiscall FUN_1008b730(void *this,byte *param_1,int param_2,int param_3,int param_4);
undefined4 FUN_1008ba30(int param_1,int param_2);
void __thiscall FUN_1008ba60(void *this,byte *param_1,uint param_2,undefined4 *param_3);
void __thiscall FUN_1008ba90(void *this,byte *param_1,uint param_2);
void __thiscall FUN_1008bae0(void *this,undefined4 *param_1,uint param_2);
int __thiscall FUN_1008bb50(void *this,int param_1,int param_2,int param_3,int param_4,undefined4 param_5,byte *param_6,char *param_7);
void __thiscall FUN_1008be90(void *this,byte *param_1,int param_2);
undefined4 __thiscall FUN_1008beb0(void *this,byte *param_1,int param_2,int param_3,int param_4);
void __thiscall FUN_1008bfd0(void *this,ushort *param_1);
uint __fastcall FUN_1008c010(void *param_1);
undefined4 __fastcall FUN_1008c030(void *param_1);
int __fastcall FUN_1008c090(int *param_1);
void __thiscall FUN_1008c0a0(void *this,undefined4 *param_1,uint param_2);
void __thiscall FUN_1008c120(void *this,uint param_1);
void __fastcall FUN_1008c290(undefined4 *param_1);
undefined4 * __thiscall FUN_1008c2b0(void *this,byte param_1);
void __fastcall FUN_1008c2d0(undefined4 *param_1);
undefined4 __thiscall FUN_1008c2e0(void *this,undefined4 param_1,int param_2);
void __thiscall FUN_1008c380(void *this,double param_1);
void FUN_1008c3a0(undefined4 param_1);
uint __thiscall FUN_1008c430(void *this,uint param_1,int param_2);
undefined4 __thiscall FUN_1008c4b0(void *this,int param_1,byte *param_2);
void FUN_1008c650(void);
void __fastcall FUN_1008c6b0(int param_1);
uint __thiscall FUN_1008c8d0(void *this,int param_1);
undefined4 __cdecl FUN_1008c900(int param_1);
void FUN_1008ca00(void);
void __cdecl FUN_1008ca20(undefined4 param_1,undefined4 param_2);
void __cdecl FUN_1008ca50(undefined4 param_1,int param_2,float param_3,uint param_4);
void FUN_1008cab0(undefined param_1,undefined param_2,undefined param_3,int param_4,undefined4 param_5);
void __cdecl FUN_1008cae0(int *param_1,undefined4 param_2);
void __cdecl FUN_1008cb10(int param_1,int param_2);
void FUN_1008cbd0(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
void __thiscall FUN_1008cc60(void *this,byte *param_1);
void __cdecl FUN_1008ccc0(int param_1);
void FUN_1008cdb0(void);
void __thiscall FUN_1008d010(void *this,void *param_1);
void __thiscall FUN_1008d040(void *this,void *param_1);
void __thiscall FUN_1008d070(void *this,void *param_1);
void __thiscall FUN_1008d0a0(void *this,void *param_1);
void __fastcall FUN_1008d0d0(int param_1);
void __fastcall FUN_1008d170(int param_1);
void __thiscall CBasePlayerItem::FallThink(CBasePlayerItem *this);
void __thiscall CBasePlayerItem::Materialize(CBasePlayerItem *this);
void __thiscall CBasePlayerItem::AttemptToMaterialize(CBasePlayerItem *this);
void __fastcall FUN_1008d360(int *param_1);
void __thiscall CBasePlayerItem::DefaultTouch(CBasePlayerItem *this,CBaseEntity *param_1);
undefined4 __cdecl FUN_1008d4e0(float param_1,float param_2,int param_3);
void __fastcall FUN_1008d510(int *param_1);
void __thiscall CBasePlayerItem::DestroyItem(CBasePlayerItem *this);
undefined4 __thiscall FUN_1008d880(void *this,undefined4 param_1);
void __fastcall FUN_1008d990(int *param_1);
undefined4 __thiscall FUN_1008d9b0(void *this,undefined4 param_1);
undefined4 __thiscall FUN_1008da40(void *this,int param_1);
void __thiscall FUN_1008db40(void *this,undefined4 param_1);
bool __thiscall FUN_1008dbc0(void *this,int param_1,undefined4 param_2,int param_3,undefined4 param_4);
bool __thiscall FUN_1008dc70(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3);
undefined4 __fastcall FUN_1008dcd0(int *param_1);
undefined4 __thiscall FUN_1008dd90(void *this,int param_1,int param_2,undefined4 param_3,char *param_4,undefined4 param_5,undefined4 param_6);
undefined4 __thiscall FUN_1008de50(void *this,int param_1,undefined4 param_2,float param_3);
undefined4 __fastcall FUN_1008def0(int param_1);
void __fastcall FUN_1008df90(int param_1);
void __thiscall CBasePlayerAmmo::Materialize(CBasePlayerAmmo *this);
void __thiscall CBasePlayerAmmo::DefaultTouch(CBasePlayerAmmo *this,CBaseEntity *param_1);
void * __thiscall FUN_1008e190(void *this,void *param_1);
float10 __thiscall FUN_1008e280(void *this,float param_1);
void __cdecl weaponbox(int param_1);
void __thiscall FUN_1008e3e0(void *this,int param_1);
void __fastcall FUN_1008e450(int *param_1);
void __thiscall CWeaponBox::Kill(CWeaponBox *this);
undefined4 __thiscall FUN_1008e600(void *this,int *param_1);
undefined4 __thiscall FUN_1008e6d0(void *this,int param_1,int param_2);
int __thiscall FUN_1008e730(void *this,int param_1,byte *param_2,int param_3,int *param_4);
undefined4 __thiscall FUN_1008e810(void *this,int *param_1);
void __fastcall FUN_1008e970(int param_1);
void __cdecl infodecal(int param_1);
void __thiscall CDecal::TriggerDecal(CDecal *this,CBaseEntity *param_1,CBaseEntity *param_2,USE_TYPE param_3,float param_4);
void __thiscall CDecal::StaticDecal(CDecal *this);
void __cdecl bodyque(int param_1);
void __cdecl FUN_1008efd0(int param_1);
undefined4 * __fastcall FUN_1008f0f0(undefined4 *param_1);
void __fastcall FUN_1008f100(undefined4 *param_1);
byte * __thiscall FUN_1008f110(void *this,byte *param_1);
void __fastcall FUN_1008f180(int *param_1);
void __thiscall FUN_1008f1d0(void *this,int param_1,int param_2,int param_3);
void __thiscall FUN_1008f240(void *this,byte *param_1,undefined4 param_2);
byte * __thiscall thunk_FUN_1008f110(void *this,byte *param_1);
undefined4 __thiscall FUN_1008f270(void *this,byte *param_1);
undefined4 __thiscall FUN_1008f290(void *this,void *param_1);
undefined4 __thiscall FUN_1008f300(void *this,void *param_1);
void __thiscall FUN_1008f3a0(void *this,byte *param_1,int param_2);
void __fastcall FUN_1008f3d0(undefined4 *param_1);
void __cdecl worldspawn(int param_1);
void FUN_1008f920(void);
void __thiscall FUN_1008f990(void *this,int param_1);
void __thiscall FUN_1008fc20(void *this,void *param_1);
void __thiscall FUN_1008fc50(void *this,void *param_1);
void __thiscall FUN_1008fc80(void *this,int param_1);
void __cdecl xen_plantlight(int param_1);
void __fastcall FUN_1008fd80(int *param_1);
void __thiscall FUN_10090010(void *this,int *param_1);
void __fastcall FUN_10090060(void *param_1);
void __fastcall FUN_10090090(void *param_1);
void __cdecl xen_hair(int param_1);
void __cdecl xen_ttrigger(int param_1);
void __cdecl FUN_100902a0(undefined4 param_1,undefined4 *param_2);
void __cdecl xen_tree(int param_1);
void __fastcall FUN_10090430(int *param_1);
void __fastcall FUN_10090680(void *param_1);
undefined4 * __cdecl FUN_100908c0(int param_1,undefined4 param_2,undefined4 param_3,float *param_4);
void __cdecl xen_spore_small(int param_1);
void __cdecl xen_spore_medium(int param_1);
void __cdecl xen_spore_large(int param_1);
void __cdecl xen_hull(int param_1);
void __fastcall FUN_10090e20(int *param_1);
void __cdecl monster_zombie(int param_1);
void __fastcall FUN_10091270(int param_1);
uint __fastcall FUN_10091780(int param_1);
void __fastcall FUN_100917f6(undefined4 *param_1);
undefined4 * __thiscall FUN_1009181f(void *this,byte param_1);
float10 __thiscall FUN_100918a5(void *this,byte *param_1);
int __thiscall FUN_100918fc(void *this,byte *param_1);
void __thiscall FUN_10091987(void *this,byte *param_1);
void FUN_10091a4c(void);
void FUN_10091a64(void);
longlong __ftol(void);
int __cdecl FUN_10091ad3(char *param_1,int param_2,byte *param_3);
int __cdecl FUN_10091b24(char *param_1,byte *param_2);
char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count);
uint * __cdecl FUN_10091c80(uint *param_1,char *param_2);
int __cdecl FUN_10091d00(int *param_1);
undefined4 * __thiscall FUN_10091d82(void *this,uint *param_1);
exception * __thiscall FUN_10091da4(void *this,byte param_1);
void __thiscall exception::~exception(exception *this);
undefined4 * __thiscall FUN_10091dc5(void *this,int param_1);
undefined4 * __thiscall FUN_10091ddd(void *this,int param_1);
exception * __thiscall FUN_10091df5(void *this,byte param_1);
void __thiscall exception::~exception(exception *this);
uint __cdecl FUN_10091e16(int *param_1);
undefined4 * __fastcall FUN_10091edc(undefined4 *param_1,undefined param_2,undefined param_3);
uint __cdecl FUN_10091ef5(int *param_1,int param_2,int param_3,int param_4,int param_5);
undefined4 * __thiscall FUN_1009200c(void *this,uint **param_1);
exception * __thiscall FUN_10092024(void *this,byte param_1);
void __thiscall exception::~exception(exception *this);
undefined4 * __thiscall FUN_10092045(void *this,int param_1);
int __cdecl FUN_1009205d(int *param_1);
int * __cdecl FUN_10092077(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,int param_5);
int * __cdecl FUN_100920d1(int param_1,int param_2,int param_3,int param_4,int param_5);
int * __cdecl FUN_100921ca(int param_1,int param_2,int param_3,int param_4,int param_5);
int __cdecl FUN_10092302(int param_1,int *param_2);
void __fastcall FUN_1009233a(undefined4 param_1);
int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
void * __cdecl operator_new(uint param_1);
void __cdecl FUN_100923b6(byte *param_1,byte *param_2);
void FUN_100923f0(void);
void _test_whether_top_of_stack_is_int(void);
int * __cdecl FUN_1009260d(int *param_1);
int __cdecl FUN_1009268b(int *param_1);
void __cdecl FUN_100926d5(undefined *param_1);
uint __thiscall FUN_100926e0(void *this,int param_1);
uint __thiscall FUN_1009275e(void *this,int param_1);
uint __thiscall FUN_100927b3(void *this,int param_1);
uint __thiscall FUN_10092803(void *this,int param_1);
void __cdecl FUN_10092944(undefined *param_1);
void FUN_100929ae(void);
void FUN_10092a06(void);
int * __cdecl FUN_10092a2d(int param_1,int param_2);
void FUN_10092ac6(void);
void FUN_10092b4f(void);
int __cdecl FUN_10092b6a(char **param_1,byte *param_2);
undefined4 __cdecl FUN_10092ba6(FILE *param_1);
undefined4 __cdecl __fclose_lk(FILE *param_1);
undefined4 * __cdecl FUN_10092c23(LPCSTR param_1,char *param_2,uint param_3);
void __cdecl FUN_10092c54(LPCSTR param_1,char *param_2);
int __cdecl FUN_10092c67(byte *param_1);
uint __cdecl FUN_10092ca8(undefined4 *param_1,uint param_2,uint param_3,char **param_4);
uint __cdecl FUN_10092cd7(undefined4 *param_1,uint param_2,uint param_3,char **param_4);
void FID_conflict:__CIacos(void);
void __cdecl start(uint param_1,uint param_2);
uint __cdecl FUN_10092ec3(uint param_1);
uint __thiscall FUN_10092f32(void *this,uint param_1);
uint __thiscall FUN_10092ffe(void *this,int param_1,uint param_2);
uint __cdecl FUN_10093073(byte *param_1,byte *param_2);
void FUN_10093120(undefined1 param_1);
int __cdecl FUN_1009314f(char *param_1,byte *param_2,undefined4 *param_3);
int __cdecl FUN_100931a0(char *param_1,int param_2,byte *param_3,undefined4 *param_4);
undefined4 FUN_100931f0(undefined4 param_1,int param_2);
int entry(undefined4 param_1,int param_2,undefined4 param_3);
void __cdecl __amsg_exit(int exitCode);
void FUN_10093399(void);
void FUN_100933c2(void);
void __cdecl FUN_1009342e(int param_1);
void __cdecl FUN_1009348f(int param_1);
int __cdecl _strcmp(char *_Str1,char *_Str2);
void __thiscall FUN_10093544(void *this,uint *param_1,byte *param_2);
size_t __cdecl _strlen(char *_Str);
longlong __allmul(uint lowerBits1,uint upperBits1,uint lowerBits2,uint upperBits2);
void __fastcall FUN_10093684(void *param_1);
undefined4 FUN_10093696(void);
void FUN_100936d4(void);
void __cdecl FUN_100936fd(char *param_1);
void __cdecl __fassign(int flag,char *argument,char *number);
undefined * __cdecl FUN_100937fb(undefined8 *param_1,undefined *param_2,int param_3,int param_4);
undefined * __cdecl FUN_1009385c(undefined *param_1,int param_2,int param_3,int *param_4,char param_5);
undefined4 * __cdecl FUN_1009391e(undefined8 *param_1,undefined4 *param_2,size_t param_3);
undefined4 * __cdecl FUN_10093973(undefined4 *param_1,size_t param_2,int *param_3,char param_4);
void __cdecl FUN_10093a1a(undefined8 *param_1,undefined4 *param_2,size_t param_3,int param_4);
errno_t __cdecl __cfltcvt(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps);
void __cdecl FUN_10093afe(undefined4 *param_1,int param_2);
uint __cdecl FUN_10093b23(uint param_1,char **param_2);
int __cdecl FUN_10093c3b(char **param_1,byte *param_2,undefined4 *param_3);
void __cdecl FUN_1009437c(uint param_1,char **param_2,int *param_3);
void __cdecl FUN_100943b1(uint param_1,int param_2,char **param_3,int *param_4);
void __cdecl FUN_100943e2(char *param_1,int param_2,char **param_3,int *param_4);
undefined4 __cdecl FUN_1009441a(int *param_1);
undefined8 __cdecl FUN_10094427(int *param_1);
undefined4 __cdecl FUN_10094437(int *param_1);
uint * __cdecl FUN_10094460(uint *param_1,char param_2);
exception * __thiscall FUN_1009452d(void *this,byte param_1);
undefined4 * __thiscall FUN_10094549(void *this,uint **param_1);
undefined4 * __thiscall FUN_10094586(void *this,int param_1);
exception * __thiscall exception::operator=(exception *this,exception *param_1);
void __thiscall exception::~exception(exception *this);
void __cdecl __global_unwind2(PVOID param_1);
void __cdecl __local_unwind2(int param_1,int param_2);
void FUN_100946ea(void);
void FUN_100947c9(int param_1);
void __CxxThrowException@8(undefined4 param_1,undefined4 param_2);
void __fastcall __cintrindisp2(undefined4 param_1,int param_2);
void __fastcall __cintrindisp1(undefined4 param_1,int param_2);
void __cdecl __ctrandisp2(uint param_1,int param_2,uint param_3,int param_4);
void FUN_100948e3(void);
void FUN_100948ea(void);
void __cdecl __ctrandisp1(uint param_1,int param_2);
float10 __cdecl __fload(uint param_1,int param_2);
void __fastcall __trandisp1(undefined4 param_1,int param_2);
void __fastcall __trandisp2(undefined4 param_1,int param_2);
undefined4 __cdecl FUN_10095466(undefined4 param_1,uint param_2,ushort param_3);
float10 FUN_1009566c(void);
void * __cdecl _malloc(size_t _Size);
void * __cdecl __nh_malloc(size_t _Size,int _NhFlag);
void __cdecl FUN_10095a29(uint *param_1);
void FUN_10095a90(void);
void FUN_10095aef(void);
int __thiscall FUN_10095b25(void *this,byte **param_1,byte *param_2,undefined4 *param_3);
uint __thiscall FUN_1009654a(void *this,uint param_1);
uint __cdecl FUN_10096581(byte **param_1);
void __cdecl FUN_1009659b(uint param_1,char **param_2);
uint __cdecl FUN_100965b2(int *param_1,byte **param_2);
float10 __fastcall __startTwoArgErrorHandling(undefined4 param_1,uint param_2,undefined2 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8);
float10 __fastcall __startOneArgErrorHandling(undefined4 param_1,uint param_2,ushort param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6);
undefined1 (*) [10] __cdecl FUN_10096850(undefined1 (*__return_storage_ptr__) [10]);
void __load_CW(undefined4 param_1);
undefined4 __convertTOStoQNaN(void);
uint __fastcall __fload_withFB(undefined4 param_1,int param_2);
uint __cdecl FUN_100968d8(undefined4 param_1,uint param_2);
void FUN_100968ee(void);
void __fastcall __math_exit(undefined4 param_1,uint param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
void __fastcall __check_range_exit(undefined4 param_1,uint param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7);
undefined4 __cdecl FUN_100969dc(int param_1,int param_2,double param_3,double *param_4);
undefined4 __cdecl FUN_10096b0c(double param_1);
void FUN_10096b71(void);
void __cdecl __exit(int _Code);
void FUN_10096bc0(void);
void __cdecl FUN_10096bde(UINT param_1,int param_2,int param_3);
void FUN_10096c83(void);
void FUN_10096c8c(void);
void __cdecl FUN_10096c95(undefined **param_1,undefined **param_2);
int ** __cdecl FUN_10096caf(int **param_1,uint *param_2);
void FUN_10096e3a(void);
void FUN_10096f88(void);
SIZE_T __cdecl FUN_10096fde(undefined *param_1);
void FUN_10097048(void);
void FUN_100970c3(void);
void __cdecl FUN_100970cc(undefined4 *param_1);
int FUN_100970f9(void);
undefined4 __cdecl FUN_10097241(int param_1);
void FUN_1009729e(void);
undefined4 __cdecl FUN_10097365(uint param_1);
undefined4 __cdecl FUN_10097418(undefined4 param_1);
uint __cdecl FUN_10097460(int param_1);
void __cdecl FUN_1009748b(uint *param_1,int param_2);
int * __cdecl FUN_100977b4(uint *param_1);
undefined4 * FUN_10097abd(void);
int __cdecl FUN_10097b6e(int param_1);
undefined4 __cdecl FUN_10097c69(uint *param_1,int param_2,int param_3);
undefined4 FUN_10098030(void);
undefined ** FUN_10098381(void);
void __cdecl FUN_100984c5(undefined **param_1);
void __cdecl FUN_1009851b(int param_1);
int __cdecl FUN_100985dd(undefined *param_1,int **param_2,uint *param_3);
void __cdecl FUN_10098634(int param_1,int param_2,byte *param_3);
int * __cdecl FUN_10098679(int *param_1);
int __cdecl FUN_10098881(int **param_1,int *param_2,int *param_3);
undefined4 __cdecl FUN_100989a5(int param_1,int **param_2,int **param_3,uint param_4);
int FUN_10098a4e(void);
undefined4 __cdecl FUN_10098bd6(undefined4 param_1);
void * __cdecl _memset(void *_Dst,int _Val,size_t _Size);
void __cdecl FUN_10098d14(uint param_1);
void __cdecl FUN_10098d43(int param_1,int param_2);
void __cdecl FUN_10098d66(uint param_1);
void __cdecl FUN_10098d95(int param_1,int param_2);
undefined4 __cdecl FUN_10098db8(void **param_1);
void __cdecl FUN_10098e45(int param_1,int *param_2);
undefined4 __cdecl FUN_10098e6f(uint param_1);
undefined4 __cdecl FUN_10098ecc(uint param_1);
void __cdecl __freebuf(FILE *_File);
int __cdecl FUN_10098f7a(int *param_1);
int __cdecl FUN_10098fa9(int *param_1);
undefined4 __cdecl FUN_10098fd7(int *param_1);
int __cdecl FUN_1009903c(int param_1);
undefined4 * __cdecl FUN_100990e0(LPCSTR param_1,char *param_2,uint param_3,undefined4 *param_4);
undefined4 * FUN_10099250(void);
int __cdecl FUN_10099318(uint param_1,char *param_2,uint param_3);
int __cdecl FUN_1009937d(DWORD param_1,char *param_2,uint param_3);
undefined4 * __cdecl FUN_10099510(undefined4 *param_1,undefined4 *param_2,uint param_3);
uint * __cdecl FUN_10099845(int param_1,uint *param_2);
undefined4 __cdecl FUN_10099a8b(int param_1,uint *param_2);
uint * FUN_10099ba6(void);
uint * __cdecl FUN_10099c5f(uint *param_1,uint *param_2,undefined4 *param_3,undefined4 *param_4);
void __cdecl FUN_10099d7a(uint *param_1,int param_2);
undefined4 __cdecl FUN_10099d9f(char *param_1,byte *param_2);
void __cdecl FUN_10099e6b(uint *param_1,uint *param_2);
int __cdecl FUN_10099ebe(LCID param_1,uint param_2,char *param_3,int param_4,LPWSTR param_5,int param_6,UINT param_7,int param_8);
int __cdecl FUN_1009a0e2(char *param_1,int param_2);
BOOL __cdecl FUN_1009a10d(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,int param_7);
undefined4 FUN_1009a256(void);
void FUN_1009a2aa(void);
void __cdecl FUN_1009a2c8(int param_1);
DWORD * FUN_1009a2db(void);
void __cdecl FUN_1009a342(undefined *param_1);
void FUN_1009a3ee(void);
void FUN_1009a5aa(void);
void FUN_1009a5fe(void);
void FUN_1009a6b7(void);
void __cdecl FUN_1009a750(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5);
undefined4 * FUN_1009a904(void);
void performExitRoutine(void);
void __cdecl executeExitProcedure(DWORD exitCode);
undefined4 __cdecl FUN_1009abf3(int param_1,int param_2);
void __cdecl FUN_1009ac3c(int param_1,int param_2);
undefined4 __cdecl FUN_1009ac92(int param_1,int param_2);
void __cdecl FUN_1009ad1e(int param_1,undefined4 *param_2);
void __cdecl FUN_1009ad39(undefined4 *param_1);
undefined4 __cdecl FUN_1009ad45(int *param_1);
void __cdecl FUN_1009ad60(uint *param_1,uint param_2);
undefined4 __cdecl FUN_1009aded(ushort *param_1,uint *param_2,int *param_3);
void __cdecl FUN_1009af59(ushort *param_1,uint *param_2);
void __cdecl FUN_1009af6f(ushort *param_1,uint *param_2);
undefined4 __cdecl FUN_1009af85(ushort *param_1,undefined4 *param_2);
void __thiscall FUN_1009afff(void *this,uint *param_1,byte *param_2);
void __thiscall FUN_1009b02c(void *this,undefined4 *param_1,byte *param_2);
void __thiscall FUN_1009b05a(void *this,uint *param_1,byte *param_2);
undefined4 __thiscall FUN_1009b087(void *this,ushort *param_1,byte **param_2,byte *param_3,int param_4,int param_5,int param_6,int param_7);
uint __thiscall FUN_1009b558(void *this,undefined4 *param_1,byte **param_2,byte *param_3,int param_4);
void FUN_1009b594(void);
void FUN_1009b5a7(void);
uint __thiscall FUN_1009b5bb(void *this,uint param_1,uint param_2);
void __thiscall FUN_1009b5f0(void *this,uint param_1,uint param_2);
uint __cdecl FUN_1009b631(uint param_1);
uint __cdecl FUN_1009b6c3(uint param_1);
uint __cdecl FUN_1009b74c(byte param_1);
uint __cdecl FUN_1009b789(uint param_1);
uint __thiscall FUN_1009b7f8(void *this,uint param_1);
void __cdecl FUN_1009b8c3(undefined4 *param_1,int param_2,int param_3);
int * __cdecl FUN_1009b93a(undefined4 param_1,undefined4 param_2,int *param_3,uint *param_4);
void __cdecl FUN_1009b996(uint *param_1,uint *param_2);
uint * __cdecl copyString(uint *destination,uint *source);
uint * __cdecl FUN_1009ba60(uint *param_1,uint *param_2);
undefined4 * __cdecl FUN_1009bb40(undefined4 *param_1,undefined4 *param_2,uint param_3);
void __cdecl __fptrap(void);
DWORD __cdecl FUN_1009be7e(uint param_1,LONG param_2,DWORD param_3);
DWORD __cdecl FUN_1009bee3(uint param_1,LONG param_2,DWORD param_3);
void __cdecl FUN_1009bf56(undefined4 *param_1);
byte __cdecl FUN_1009bf9a(uint param_1);
LPSTR __cdecl FUN_1009bfc3(LPSTR param_1,WCHAR param_2);
LPSTR __cdecl FUN_1009c01c(LPSTR param_1,WCHAR param_2);
undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4);
undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4);
int FUN_1009c175(int **param_1);
void __cdecl FUN_1009c1d9(uint param_1,int *param_2,ushort *param_3);
uint __cdecl FUN_1009c2a9(LPWSTR param_1,byte *param_2,uint param_3);
uint __cdecl FUN_1009c306(LPWSTR param_1,byte *param_2,uint param_3);
longlong __fastcall __allshl(byte shiftAmount,int upperBits);
uint __cdecl FUN_1009c3ef(byte **param_1);
uint __cdecl FUN_1009c4f4(uint param_1,char **param_2);
float10 __cdecl FUN_1009c562(undefined8 param_1,short param_2);
float10 __cdecl FUN_1009c5cb(undefined8 param_1,short param_2);
undefined4 __cdecl FUN_1009c5ef(int param_1,uint param_2);
float10 __cdecl FUN_1009c649(uint param_1,uint param_2,int *param_3);
float10 __cdecl __frnd(double param_1);
double __cdecl __copysign(double _Number,double _Sign);
float10 __cdecl FUN_1009c73d(undefined4 param_1,uint param_2);
float10 __cdecl FUN_1009c778(uint param_1,undefined4 param_2);
float10 __cdecl FUN_1009c85f(int param_1,uint param_2,int param_3,uint param_4);
int __cdecl FUN_1009cb36(int param_1,uint param_2);
void __thiscall FUN_1009cbc8(void *this,byte *param_1,byte **param_2,undefined *param_3);
undefined * __thiscall FUN_1009cbdf(void *this,byte *param_1,byte **param_2,undefined *param_3,uint param_4);
void __cdecl FUN_1009ce7c(uint param_1);
DWORD * FUN_1009ceef(void);
DWORD * FUN_1009cef8(void);
uint FUN_1009cf01(void);
undefined4 __cdecl FUN_1009d024(uint param_1,HANDLE param_2);
undefined4 __cdecl FUN_1009d0a0(uint param_1);
undefined4 __cdecl FUN_1009d11f(uint param_1);
uint __cdecl FUN_1009d161(HANDLE param_1,uint param_2);
void __cdecl FUN_1009d208(uint param_1);
void __cdecl FUN_1009d267(uint param_1);
DWORD __cdecl FUN_1009d289(uint param_1);
uint __cdecl FUN_1009d333(LPCSTR param_1,uint param_2,uint param_3,uint param_4);
uint __cdecl FUN_1009d693(char **param_1);
void __cdecl FUN_1009d9e1(undefined4 *param_1);
void __cdecl FUN_1009dd46(char *param_1);
uint __cdecl FUN_1009de48(int param_1);
void __cdecl FUN_1009df6a(char *param_1);
void __cdecl FUN_1009dfa1(int param_1);
undefined4 FUN_1009dfef(void);
int __cdecl FUN_1009e240(byte *param_1,byte *param_2);
byte * __cdecl FUN_1009e280(byte *param_1,byte *param_2);
undefined4 __thiscall FUN_1009e2ba(void *this,char *param_1,undefined2 *param_2,int param_3);
void __thiscall FUN_1009e437(void *this,int param_1,int param_2,byte **param_3);
void FUN_1009e48f(void);
uint lpLocaleEnumProc_1009e516(char *param_1);
void FUN_1009e71a(void);
uint lpLocaleEnumProc_1009e770(char *param_1);
void FUN_1009e82d(void);
uint lpLocaleEnumProc_1009e864(char *param_1);
void FUN_1009e8ea(void);
void __cdecl FUN_1009e904(byte *param_1);
undefined4 __cdecl FUN_1009e96a(short param_1);
undefined4 __cdecl FUN_1009e989(int param_1,int param_2);
undefined4 FUN_1009e9eb(void);
int FUN_1009ea21(uint param_1,LCTYPE param_2,char *param_3,int param_4);
int __cdecl FUN_1009eb07(char *param_1);
int __cdecl FUN_1009eb40(char *param_1);
LONG __cdecl FUN_1009eb61(int param_1,_EXCEPTION_POINTERS *param_2);
int * __cdecl FUN_1009ec9f(int param_1,int *param_2);
undefined4 __cdecl FUN_1009ecd9(int param_1);
int __cdecl FUN_1009ee86(int param_1);
undefined4 __cdecl FUN_1009eed0(int param_1);
void FUN_1009ef03(void);
void FUN_1009ef2c(void);
void FUN_1009f0c1(void);
int __cdecl FUN_1009f0dd(undefined4 param_1,undefined4 param_2,undefined4 param_3);
undefined4 __cdecl addWithCarry(uint firstNumber,uint secondNumber,uint *result);
void __cdecl ___add_12(uint *firstNumber,uint *secondNumber);
void __cdecl FUN_1009f1e5(uint *param_1);
void __cdecl FUN_1009f213(uint *param_1);
void __cdecl FUN_1009f240(char *param_1,int param_2,uint *param_3);
void __cdecl FUN_1009f307(int *param_1,int *param_2);
void __cdecl FUN_1009f527(int *param_1,uint param_2,int param_3);
int __cdecl FUN_1009f5a3(int param_1,int param_2);
undefined4 __cdecl FUN_1009f787(DWORD *param_1);
uint __cdecl FUN_1009f909(int param_1,uint param_2);
DWORD * FUN_1009f94f(void);
undefined4 __cdecl FUN_1009f958(uint param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6);
bool __cdecl FUN_1009fc23(FARPROC param_1);
void FUN_1009fc3b(void);
void FUN_1009fcb4(void);
float10 __cdecl FUN_1009fd0a(int param_1,double param_2);
float10 __cdecl FUN_1009fd5e(int param_1,double param_2,double param_3);
float10 __cdecl FUN_1009fdbe(uint param_1,uint param_2,undefined8 param_3,double param_4,uint param_5);
float10 __cdecl FUN_1009fe56(uint param_1,uint param_2,undefined8 param_3,undefined8 param_4,double param_5,uint param_6);
void __cdecl FUN_1009fefb(uint *param_1,uint *param_2,uint param_3,uint param_4,undefined8 *param_5,undefined8 *param_6);
bool __cdecl FUN_100a01ae(uint param_1,double *param_2,uint param_3);
float10 __cdecl FUN_100a03c5(int param_1,int param_2);
void __cdecl FUN_100a044d(int param_1);
undefined * __cdecl FUN_100a0475(int param_1);
int __cdecl FUN_100a049a(byte param_1);
undefined4 FUN_100a04c7(void);
int FUN_100a04ca(void);
int FUN_100a04d8(void);
int FUN_100a04e7(undefined4 param_1,undefined4 param_2);
void __set_statfp(undefined4 param_1);
int __cdecl FUN_100a0560(uint param_1,char *param_2,char *param_3);
int __cdecl FUN_100a05c5(uint param_1,char *param_2,char *param_3);
float10 __cdecl FUN_100a079e(double param_1,int param_2);
int __cdecl FUN_100a0984(uint param_1,int param_2);
int __cdecl FUN_100a09dd(uint param_1,int param_2);
undefined * FUN_100a0b02(void);
undefined * FUN_100a0b91(void);
uint ** FUN_100a0c26(void);
int __cdecl FUN_100a0e73(byte *param_1,uint param_2,byte *param_3,int *param_4,undefined *param_5);
void __cdecl FUN_100a0f6d(char param_1,int *param_2,byte **param_3,uint *param_4,int param_5);
void __cdecl FUN_100a135c(char *param_1,char **param_2,int *param_3);
void __cdecl FUN_100a1383(int param_1,uint param_2,char **param_3,uint *param_4);
void __cdecl FUN_100a13f2(int param_1,char **param_2,uint *param_3);
void __cdecl FUN_100a143b(byte *param_1,int param_2,byte **param_3,uint *param_4,int param_5);
undefined4 __cdecl FUN_100a170a(int param_1,LCID param_2,LCTYPE param_3,char **param_4);
BOOL __cdecl FUN_100a1848(DWORD param_1,LPCWSTR param_2,int param_3,undefined4 *param_4,UINT param_5,LCID param_6);
char * __cdecl FUN_100a1a0d(uint param_1,char *param_2,uint param_3);
void __cdecl FUN_100a1a3a(uint param_1,char *param_2,uint param_3,int param_4);
char * __cdecl FUN_100a1a96(uint param_1,char *param_2,uint param_3);
char * __cdecl FUN_100a1adb(int param_1,int param_2,char *param_3,uint param_4);
void FUN_100a1b0c(int param_1,int param_2,char *param_3,uint param_4,int param_5);
char * __cdecl FUN_100a1b92(int param_1,int param_2,char *param_3,uint param_4);
uint __thiscall FUN_100a1bb0(void *this,byte *param_1,byte *param_2);
void * __cdecl FUN_100a1c80(byte *param_1,char *param_2,void *param_3);
void FUN_100a1d81(void);
int __cdecl FUN_100a1df1(uint param_1,int param_2);
void FUN_100a1e52(void);
void FUN_100a1e96(void);
bool __cdecl FUN_100a213e(int *param_1);
void __cdecl FUN_100a22ea(int param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,int param_7,int param_8,int param_9,int param_10,int param_11);
int __cdecl FUN_100a242a(LCID param_1,LCTYPE param_2,LPWSTR param_3,int param_4,UINT param_5);
int __cdecl FUN_100a253d(LCID param_1,LCTYPE param_2,LPSTR param_3,int param_4,UINT param_5);
uchar * __cdecl FUN_100a267c(uchar *param_1);
int __cdecl __mbsnbicoll(uchar *_Str1,uchar *_Str2,size_t _MaxCount);
undefined4 FUN_100a2738(void);
int __cdecl FUN_100a27a6(LCID param_1,DWORD param_2,byte *param_3,int param_4,byte *param_5,int param_6,UINT param_7);
int __cdecl FUN_100a2a23(char *param_1,int param_2);
undefined4 __cdecl FUN_100a2a4e(uint *param_1,int param_2);
int __cdecl FUN_100a2bd5(uchar *param_1,size_t param_2);
uint ** __cdecl FUN_100a2c2d(uint **param_1);
uint * __cdecl FUN_100a2c94(uint *param_1,uint param_2);
uint * __cdecl FUN_100a2d2b(uint *param_1);
void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue);

