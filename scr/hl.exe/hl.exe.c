#include "hl.exe.h"



void FUN_0140100a(void)

{
  FUN_0140102a(&DAT_01414bd0);
  return;
}



void FUN_01401014(void)

{
  FUN_0140241e((int *)&LAB_01401020);
  return;
}



void __fastcall FUN_0140102a(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &PTR_FUN_0140f1d0;
  return;
}



undefined4 * __thiscall FUN_01401037(void *this,byte param_1)

{
  FUN_01401053((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0140250e((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_01401053(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0140f1d0;
  FUN_0140250e((undefined *)param_1[1]);
  return;
}



void FUN_01401063(uint *param_1)

{
  int iVar1;
  char cVar2;
  uint *puVar3;
  FILE *pFVar4;
  uint uVar5;
  uint *puVar6;
  int extraout_ECX;
  FILE *pFVar7;
  undefined1 unaff_BP;
  uint *puVar8;
  bool bVar9;
  uint local_1110 [1024];
  FILE local_110 [7];
  undefined4 uStackY_1c;
  int iVar10;
  uint *puVar11;
  
  FUN_014028c0(unaff_BP);
  pFVar7 = *(FILE **)(extraout_ECX + 4);
  iVar10 = extraout_ECX;
  FUN_0140250e((undefined *)pFVar7);
  uStackY_1c = 0x1401088;
  puVar3 = FUN_0140115e(param_1);
  puVar6 = local_1110;
  bVar9 = true;
  cVar2 = *(char *)puVar3;
  puVar11 = puVar3;
  iVar1 = extraout_ECX;
  while (cVar2 != '\0') {
    if ((bVar9) && (*(char *)puVar3 == '@')) {
      pFVar7 = local_110;
      puVar8 = puVar3;
      while( true ) {
        puVar3 = (uint *)((int)puVar8 + 1);
        cVar2 = *(char *)puVar3;
        if ((cVar2 == '\0') || (cVar2 == ' ')) break;
        *(char *)&pFVar7->_ptr = cVar2;
        pFVar7 = (FILE *)((int)&pFVar7->_ptr + 1);
        puVar8 = puVar3;
      }
      *(undefined *)&pFVar7->_ptr = 0;
      if (*(char *)puVar3 != '\0') {
        puVar3 = (uint *)((int)puVar8 + 2);
      }
      uStackY_1c = 0x14010dd;
      pFVar4 = (FILE *)FUN_014028a8((LPCSTR)local_110,&DAT_014110a8);
      if (pFVar4 == (FILE *)0x0) {
        pFVar4 = local_110;
        uStackY_1c = 0x14010f6;
        FUN_01402836((byte *)s_Parameter_file___s__not_found__s_0141107c);
      }
      else {
        while( true ) {
          uVar5 = FUN_014027fa((byte **)pFVar4);
          cVar2 = (char)uVar5;
          if (cVar2 == -1) break;
          if (cVar2 == '\n') {
            cVar2 = ' ';
          }
          *(char *)puVar6 = cVar2;
          puVar6 = (uint *)((int)puVar6 + 1);
        }
        *(char *)puVar6 = ' ';
        puVar6 = (uint *)((int)puVar6 + 1);
        FUN_0140277d(pFVar4);
      }
    }
    else {
      pFVar4 = (FILE *)(int)*(char *)puVar3;
      uVar5 = FUN_014025ec(pFVar7,(int)pFVar4);
      bVar9 = uVar5 != 0;
      *(char *)puVar6 = *(char *)puVar3;
      puVar6 = (uint *)((int)puVar6 + 1);
      puVar3 = (uint *)((int)puVar3 + 1);
    }
    iVar1 = iVar10;
    pFVar7 = pFVar4;
    cVar2 = *(char *)puVar3;
  }
  *(char *)puVar6 = '\0';
  FUN_0140250e((undefined *)puVar11);
  uStackY_1c = 0x1401152;
  puVar6 = FUN_0140115e(local_1110);
  *(uint **)(iVar1 + 4) = puVar6;
  return;
}



uint * __cdecl FUN_0140115e(uint *param_1)

{
  size_t sVar1;
  uint *puVar2;
  
  if (param_1 == (uint *)0x0) {
    return (uint *)0x0;
  }
  sVar1 = _strlen((char *)param_1);
  puVar2 = (uint *)dynamische_Speicherallokation(sVar1 + 1);
  FUN_014028f0(puVar2,param_1);
  return puVar2;
}



void __thiscall FUN_0140118a(void *this,char *param_1)

{
  char cVar1;
  uint *_Str;
  size_t sVar2;
  uint *_Dst;
  undefined4 *puVar3;
  uint uVar4;
  char *_Str_00;
  
  if (((*(int *)((int)this + 4) != 0) && (param_1 != (char *)0x0)) && (*param_1 != '\0')) {
    while( true ) {
      _Str = *(uint **)((int)this + 4);
      sVar2 = _strlen((char *)_Str);
      _Dst = FUN_01402e10(_Str,param_1);
      if (_Dst == (uint *)0x0) break;
      puVar3 = (undefined4 *)((int)_Dst + 1);
      if (puVar3 == (undefined4 *)0x0) {
LAB_0140120a:
        Initialize_Memory(_Dst,0,(int)puVar3 - (int)_Dst);
      }
      else {
        while ((cVar1 = *(char *)puVar3, cVar1 != '\0' && (cVar1 != '-'))) {
          if ((cVar1 == '+') ||
             (puVar3 = (undefined4 *)((int)puVar3 + 1), puVar3 == (undefined4 *)0x0)) break;
        }
        if ((puVar3 == (undefined4 *)0x0) || (*(char *)puVar3 == '\0')) goto LAB_0140120a;
        uVar4 = (sVar2 - (int)puVar3) + (int)_Str;
        FUN_01402ad0(_Dst,puVar3,uVar4);
        *(undefined *)(uVar4 + (int)_Dst) = 0;
      }
    }
    _Str_00 = *(char **)((int)this + 4);
    sVar2 = _strlen(_Str_00);
    while (_Str_00[sVar2 - 1] == ' ') {
      sVar2 = _strlen(_Str_00);
      *(undefined *)((sVar2 - 1) + *(int *)((int)this + 4)) = 0;
      _Str_00 = *(char **)((int)this + 4);
      sVar2 = _strlen(_Str_00);
    }
  }
  return;
}



void __thiscall FUN_0140124d(void *this,uint *param_1,uint *param_2)

{
  uint Memory_size;
  size_t sVar1;
  size_t sVar2;
  uint *puVar3;
  
  sVar1 = _strlen((char *)param_1);
  if (param_2 != (uint *)0x0) {
    sVar2 = _strlen((char *)param_2);
    sVar1 = sVar1 + 1 + sVar2;
  }
  if (*(int *)((int)this + 4) == 0) {
    puVar3 = (uint *)dynamische_Speicherallokation(sVar1 + 1);
    *(uint **)((int)this + 4) = puVar3;
    FUN_014028f0(puVar3,param_1);
    if (param_2 != (uint *)0x0) {
      FUN_01402900(*(uint **)((int)this + 4),(uint *)&DAT_014110ac);
      FUN_01402900(*(uint **)((int)this + 4),param_2);
    }
  }
  else {
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0xc))(param_1);
    sVar2 = _strlen(*(char **)((int)this + 4));
    Memory_size = sVar1 + 3 + sVar2;
    puVar3 = (uint *)dynamische_Speicherallokation(Memory_size);
    Initialize_Memory(puVar3,0,Memory_size);
    FUN_014028f0(puVar3,*(uint **)((int)this + 4));
    FUN_01402900(puVar3,(uint *)&DAT_014110ac);
    FUN_01402900(puVar3,param_1);
    if (param_2 != (uint *)0x0) {
      FUN_01402900(puVar3,(uint *)&DAT_014110ac);
      FUN_01402900(puVar3,param_2);
    }
    FUN_0140250e(*(undefined **)((int)this + 4));
    *(uint **)((int)this + 4) = puVar3;
  }
  return;
}



void __thiscall FUN_01401325(void *this,undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0xc))(param_1);
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x10))(unaff_retaddr,param_1);
  return;
}



void __thiscall FUN_01401344(void *this,undefined4 param_1,undefined4 param_2)

{
  char local_44 [64];
  
  FUN_01402e90(local_44,0x40,&DAT_014110b0);
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x18))(param_1,local_44);
  return;
}



uint * __thiscall FUN_0140137a(void *this,char *param_1,undefined4 *param_2)

{
  char cVar1;
  uint *puVar2;
  uint *puVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = 0;
  if (*(uint **)((int)this + 4) == (uint *)0x0) {
    puVar2 = (uint *)0x0;
  }
  else {
    puVar2 = FUN_01402e10(*(uint **)((int)this + 4),param_1);
    if ((puVar2 != (uint *)0x0) && (param_2 != (undefined4 *)0x0)) {
      *param_2 = 0;
      for (puVar3 = puVar2; (*(char *)puVar3 != '\0' && (*(char *)puVar3 != ' '));
          puVar3 = (uint *)((int)puVar3 + 1)) {
      }
      pcVar4 = (char *)((int)puVar3 + 1);
      iVar6 = (int)&DAT_01414b50 - (int)pcVar4;
      do {
        cVar1 = *pcVar4;
        if ((cVar1 == '\0') || (cVar1 == ' ')) break;
        pcVar4[iVar6] = cVar1;
        iVar5 = iVar5 + 1;
        pcVar4 = pcVar4 + 1;
      } while (iVar5 < 0x80);
      (&DAT_01414b50)[iVar5] = 0;
      *param_2 = &DAT_01414b50;
    }
  }
  return puVar2;
}



undefined4 __cdecl CreateInterface(char *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  code **ppcVar3;
  
  ppcVar3 = DAT_01414bd8;
                    // 0x140f  1  CreateInterface
  while( true ) {
    if (ppcVar3 == (code **)0x0) {
      if (param_2 != (undefined4 *)0x0) {
        *param_2 = 1;
      }
      return 0;
    }
    iVar1 = _strcmp((char *)ppcVar3[1],param_1);
    if (iVar1 == 0) break;
    ppcVar3 = (code **)ppcVar3[2];
  }
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = 0;
  }
  uVar2 = (**ppcVar3)();
  return uVar2;
}



void __cdecl FUN_01401461(LPCSTR param_1)

{
  HMODULE pHVar1;
  char local_204 [512];
  
  pHVar1 = LoadLibraryA(param_1);
  if (pHVar1 == (HMODULE)0x0) {
    FUN_01402e90(local_204,0x200,(byte *)s__s_dll_014110b4);
    LoadLibraryA(local_204);
  }
  return;
}



void __cdecl FUN_014014a2(HMODULE param_1)

{
  if (param_1 != (HMODULE)0x0) {
    FreeLibrary(param_1);
  }
  return;
}



FARPROC __cdecl FUN_014014b4(HMODULE param_1)

{
  FARPROC pFVar1;
  
  if (param_1 == (HMODULE)0x0) {
    return (FARPROC)0x0;
  }
  pFVar1 = GetProcAddress(param_1,s_CreateInterface_014110bc);
  return pFVar1;
}



undefined * FUN_014014ce(void)

{
  return CreateInterface;
}



undefined * FUN_014014fb(void)

{
  char cVar1;
  DWORD DVar2;
  char *pcVar3;
  size_t sVar4;
  CHAR local_108 [260];
  
  local_108[0] = '\0';
  DAT_01414ce8 = 0;
  DVar2 = GetModuleFileNameA((HMODULE)0x0,local_108,0x104);
  if (DVar2 != 0) {
    GetLongPathNameA(local_108,&DAT_01414ce8,0x104);
    pcVar3 = _strrchr(&DAT_01414ce8,0x5c);
    if (*pcVar3 != '\0') {
      pcVar3[1] = '\0';
    }
    sVar4 = _strlen(&DAT_01414ce8);
    if (0 < (int)sVar4) {
      cVar1 = (&DAT_01414ce7)[sVar4];
      if ((cVar1 == '\\') || (cVar1 == '/')) {
        (&DAT_01414ce7)[sVar4] = '\0';
      }
    }
  }
  return &DAT_01414ce8;
}



void __cdecl FUN_01401578(char **param_1)

{
  byte *pbVar1;
  uint uVar2;
  int iVar3;
  void *this;
  char *this_00;
  
  *param_1 = s_hw_dll_01411100;
  pbVar1 = (byte *)(**(code **)(*(int *)PTR_DAT_0141156c + 0x10))
                             (s_EngineDLL_014110f4,s_hw_dll_01411100);
  this_00 = s_hw_dll_01411100;
  uVar2 = FUN_0140a6c0(this,pbVar1,(byte *)s_hw_dll_01411100);
  if (uVar2 == 0) {
    *param_1 = s_hw_dll_01411100;
  }
  else {
    uVar2 = FUN_0140a6c0(this_00,pbVar1,(byte *)s_sw_dll_014110ec);
    if (uVar2 == 0) {
      *param_1 = s_sw_dll_014110ec;
    }
  }
  iVar3 = (**(code **)(*(int *)PTR_DAT_01411040 + 8))(s__soft_014110e4,0);
  if (iVar3 == 0) {
    iVar3 = (**(code **)(*(int *)PTR_DAT_01411040 + 8))(s__software_014110d8,0);
    if (iVar3 == 0) {
      iVar3 = (**(code **)(*(int *)PTR_DAT_01411040 + 8))(&DAT_014110d4,0);
      if (iVar3 == 0) {
        iVar3 = (**(code **)(*(int *)PTR_DAT_01411040 + 8))(&DAT_014110cc,0);
        if (iVar3 == 0) goto LAB_0140161b;
      }
      *param_1 = s_hw_dll_01411100;
      goto LAB_0140161b;
    }
  }
  *param_1 = s_sw_dll_014110ec;
LAB_0140161b:
  (**(code **)(*(int *)PTR_DAT_0141156c + 0x14))(s_EngineDLL_014110f4,*param_1);
  return;
}



bool FUN_01401632(void)

{
  int iVar1;
  
  (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_ScreenBPP_01411190,0x10);
  (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_ScreenHeight_01411180,0x280);
  (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_ScreenWidth_01411174,0x1e0);
  (**(code **)(*(int *)PTR_DAT_0141156c + 0x14))(s_EngineDLL_014110f4,s_hw_dll_01411100);
  iVar1 = MessageBox((HWND)0x0,s_The_specified_video_mode_is_not_s_01411108,
                     s_Video_mode_change_failure_01411158,0x31);
  return (bool)('\x01' - (iVar1 != 1));
}



bool __cdecl FUN_0140169e(LPSTR param_1,DWORD param_2)

{
  HMODULE hModule;
  DWORD DVar1;
  
  hModule = GetModuleHandleA((LPCSTR)0x0);
  DVar1 = GetModuleFileNameA(hModule,param_1,param_2);
  return DVar1 != 0;
}



int __cdecl FUN_014016bc(uint *param_1)

{
  int iVar1;
  uint *puVar2;
  HANDLE pvVar3;
  uint local_11c [70];
  
  iVar1 = FUN_01401461(s_filesystem_stdio_dll_0141126c);
  if (iVar1 == 0) {
    puVar2 = FUN_014031d0(param_1,';');
    if (puVar2 == (uint *)0x0) {
      pvVar3 = FUN_01402fa7(s_filesystem_stdio_dll_0141126c,local_11c);
      if (pvVar3 == (HANDLE)0xffffffff) {
        MessageBox((HWND)0x0,s_Could_not_find_filesystem_dll_to_0141119c,s_Fatal_Error_01411260,0x10
                  );
      }
      else {
        MessageBox((HWND)0x0,s_Could_not_load_filesystem_dll__F_014111c8,s_Fatal_Error_01411260,0x10
                  );
        FUN_0140313c(pvVar3);
      }
    }
    else {
      MessageBox((HWND)0x0,s_Game_cannot_be_run_from_director_01411210,s_Fatal_Error_01411260,0x10);
      iVar1 = 0;
    }
  }
  return iVar1;
}



undefined4 FUN_01401746(undefined4 win_modul,undefined4 param_2,HKEY param_3)

{
  code **ppcVar1;
  undefined4 uVar2;
  DWORD DVar3;
  LPSTR pCVar4;
  int iVar5;
  char *pcVar6;
  uint uVar7;
  size_t sVar8;
  FARPROC pFVar9;
  undefined *puVar10;
  uint *puVar11;
  void *this;
  void *this_00;
  byte *pbVar12;
  byte *pbVar13;
  undefined *puVar14;
  WSADATA local_4ac;
  char local_31c [512];
  uint local_11c [64];
  HMODULE local_1c;
  undefined4 local_18;
  int *local_14;
  HMODULE local_10;
  LPCSTR local_c;
  HANDLE local_8;
  
  uVar2 = FUN_01402023(param_3,(byte *)s_filesystem_stdio_dll_0141126c,
                       (byte *)s_filesystem_stdio_dll_0141126c);
  if ((char)uVar2 == '\0') {
    local_8 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,s_ValveHalfLifeLauncherMutex_01411544);
    if (local_8 != (HANDLE)0x0) {
      GetLastError();
    }
    DVar3 = WaitForSingleObject(local_8,0);
    if ((DVar3 == 0) || (DVar3 == 0x80)) {
      WSAStartup(2,&local_4ac);
      (***(code ***)PTR_DAT_0141156c)();
      ppcVar1 = *(code ***)PTR_DAT_01411040;
      pCVar4 = GetCommandLineA();
      (**ppcVar1)(pCVar4);
      iVar5 = (**(code **)(*(int *)PTR_DAT_01411040 + 8))(s__steam_014114e4,0);
      local_18 = CONCAT31(local_18._1_3_,iVar5 != 0);
      FUN_0140169e((LPSTR)local_11c,0x100);
      pcVar6 = _strrchr((char *)local_11c,0x5c);
      pbVar12 = (byte *)(pcVar6 + 1);
      uVar7 = FUN_0140a6c0(this,(byte *)s_hl_exe_014114dc,pbVar12);
      if ((uVar7 != 0) &&
         (iVar5 = (**(code **)(*(int *)PTR_DAT_01411040 + 8))(s__game_014114d4,0), iVar5 == 0)) {
        sVar8 = _strlen((char *)pbVar12);
        pbVar12[sVar8 - 4] = 0;
        (**(code **)(*(int *)PTR_DAT_01411040 + 0x10))(s__game_014114d4,pbVar12);
      }
      pcVar6 = (char *)(**(code **)(*(int *)PTR_DAT_01411040 + 8))(s__game_014114d4,0);
      if (pcVar6 == (char *)0x0) {
        FUN_014028f0((uint *)&DAT_01414df0,(uint *)s_valve_014114cc);
      }
      else {
        _strncpy(&DAT_01414df0,pcVar6,0x104);
      }
      FUN_014032fd(0);
      FUN_0140edb8(s_mssv29_asi_014114c0);
      FUN_0140edb8(s_mssv12_asi_014114b4);
      FUN_0140edb8(s_mp3dec_asi_014114a8);
      FUN_0140edb8(s_opengl32_dll_01411498);
      iVar5 = (**(code **)(*(int *)PTR_DAT_0141156c + 8))(s_CrashInitializingVideoMode_0141147c,0);
      if (iVar5 != 0) {
        pbVar13 = (byte *)0x0;
        (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_CrashInitializingVideoMode_0141147c);
        pbVar12 = (byte *)(**(code **)(*(int *)PTR_DAT_0141156c + 0x10))
                                    (s_EngineDLL_014110f4,&DAT_014156fc,s_hw_dll_01411100);
        uVar7 = FUN_0140a6c0(this_00,pbVar12,pbVar13);
        if (uVar7 == 0) {
          iVar5 = (**(code **)(*(int *)PTR_DAT_0141156c + 8))(s_EngineD3D_01411470,0);
          if (iVar5 == 1) {
            (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_EngineD3D_01411470,0);
            pcVar6 = s_The_game_has_detected_that_the_p_014113e8;
          }
          else {
            (**(code **)(*(int *)PTR_DAT_0141156c + 0x14))(s_EngineDLL_014110f4,s_hw_dll_01411100);
            pcVar6 = s_The_game_has_detected_that_the_p_01411368;
          }
          iVar5 = MessageBox((HWND)0x0,pcVar6,s_Video_mode_change_failure_01411158,0x31);
          if (iVar5 != 1) {
            return 0;
          }
          (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_ScreenBPP_01411190,0x10);
          (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_ScreenHeight_01411180,0x280);
          (**(code **)(*(int *)PTR_DAT_0141156c + 0xc))(s_ScreenWidth_01411174,0x1e0);
        }
      }
      do {
        local_10 = (HMODULE)FUN_014016bc(local_11c);
        if (local_10 == (HMODULE)0x0) break;
        uVar2 = 0;
        pcVar6 = s_VFileSystem009_01411354;
        pFVar9 = FUN_014014b4(local_10);
        DAT_014156f8 = (int *)(*pFVar9)(pcVar6,uVar2);
        (**(code **)(*DAT_014156f8 + 4))();
        puVar14 = &DAT_0141134c;
        iVar5 = *DAT_014156f8;
        puVar10 = FUN_014014fb();
        (**(code **)(iVar5 + 0x10))(puVar10,puVar14);
        param_3._3_1_ = false;
        iVar5 = 0;
        DAT_01414ef8 = 0;
        FUN_01401578(&local_c);
        local_1c = (HMODULE)FUN_01401461(local_c);
        if (local_1c == (HMODULE)0x0) {
          FUN_0140328c(local_31c,(byte *)s_Could_not_load__s__Please_try_ag_014112f4);
          MessageBox((HWND)0x0,local_31c,s_Fatal_Error_01411260,0x10);
        }
        else {
          pFVar9 = FUN_014014b4(local_1c);
          if ((pFVar9 != (FARPROC)0x0) &&
             (local_14 = (int *)(*pFVar9)(s_VENGINE_LAUNCHER_API_VERSION002_0141132c,0),
             local_14 != (int *)0x0)) {
            iVar5 = *local_14;
            pFVar9 = FUN_014014b4(local_10);
            puVar10 = FUN_014014ce();
            uVar2 = (**(code **)(*(int *)PTR_DAT_01411040 + 4))(&DAT_01414ef8,puVar10,pFVar9);
            puVar10 = FUN_014014fb();
            iVar5 = (**(code **)(iVar5 + 4))(win_modul,puVar10,uVar2);
          }
          FUN_014014a2(local_1c);
        }
        if (iVar5 != 0) {
          if (iVar5 == 1) {
            param_3._3_1_ = true;
          }
          else if (iVar5 == 2) {
            param_3._3_1_ = FUN_01401632();
          }
        }
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(&DAT_014112f0);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__startwindowed_014112e0);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__windowed_014112d4);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__window_014112cc);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__full_014112c4);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__fullscreen_014112b8);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__soft_014110e4);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__software_014110d8);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(&DAT_014110d4);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(&DAT_014110cc);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(&DAT_014112b4);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__width_014112ac);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(&DAT_014112a8);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__height_014112a0);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__connect_01411294);
        (**(code **)(*(int *)PTR_DAT_01411040 + 0x14))(s__novid_0141128c,0);
        puVar11 = FUN_01402e10((uint *)&DAT_01414ef8,s__game_014114d4);
        if (puVar11 != (uint *)0x0) {
          (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__game_014114d4);
        }
        puVar11 = FUN_01402e10((uint *)&DAT_01414ef8,s__load_01411284);
        if (puVar11 != (uint *)0x0) {
          (**(code **)(*(int *)PTR_DAT_01411040 + 0xc))(s__load_01411284);
        }
        (**(code **)(*(int *)PTR_DAT_01411040 + 0x10))(&DAT_01414ef8,0);
        (**(code **)(*DAT_014156f8 + 8))();
        FUN_014014a2(local_10);
      } while (param_3._3_1_ != false);
      (**(code **)(*(int *)PTR_DAT_0141156c + 4))();
      ReleaseMutex(local_8);
      CloseHandle(local_8);
      WSACleanup();
    }
    else {
      MessageBox((HWND)0x0,s_Could_not_launch_game__Only_one_i_014114f0,Modul_name,0x10);
    }
  }
  return 0;
}



uint __cdecl FUN_01401d22(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  byte bVar3;
  uint *puVar4;
  uint local_8;
  
  local_8 = 0;
  bVar3 = 0x57;
  iVar2 = 0x44;
  if (0x44 < param_4) {
    do {
      *(byte *)(iVar2 + param_1) = *(byte *)(iVar2 + param_1) ^ bVar3;
      bVar3 = bVar3 + *(char *)(iVar2 + param_1) + 'W';
      iVar2 = iVar2 + 1;
    } while (iVar2 < param_4);
  }
  param_4 = 0;
  if (-1 < *(int *)(param_1 + 0x48)) {
    puVar4 = (uint *)(param_1 + 100);
    do {
      if (puVar4[2] != 0) {
        local_8 = puVar4[-2];
      }
      uVar1 = *puVar4;
      if ((int)uVar1 < (int)puVar4[-1]) {
        Initialize_Memory((void *)(puVar4[-2] + uVar1),0,puVar4[-1] - uVar1);
      }
      FUN_01402ad0((undefined4 *)puVar4[-2],(undefined4 *)(puVar4[1] + param_1),*puVar4);
      param_4 = param_4 + 1;
      puVar4 = puVar4 + 5;
    } while (param_4 <= *(int *)(param_1 + 0x48));
  }
  FUN_01401dce(param_1 + 0x44);
  (*(code *)(*(int *)(param_1 + 0x54) + -0xc))(0,1,0);
  (*(code *)(*(uint *)(param_1 + 0x4c) ^ 0x7a32bc85))(param_3);
  return local_8;
}



void __cdecl FUN_01401dce(int param_1)

{
  int iVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  LPCSTR lpProcName;
  int *piVar3;
  FARPROC *ppFVar4;
  
  piVar3 = (int *)((*(uint *)(param_1 + 0x14) ^ 0x872c3d47) + 0xc);
  iVar1 = *piVar3;
  while (iVar1 != 0) {
    hModule = LoadLibraryA((LPCSTR)((*(uint *)(param_1 + 0xc) ^ 0x49c042d1) + *piVar3));
    for (ppFVar4 = (FARPROC *)((*(uint *)(param_1 + 0xc) ^ 0x49c042d1) + piVar3[1]);
        pFVar2 = *ppFVar4, pFVar2 != (FARPROC)0x0; ppFVar4 = ppFVar4 + 1) {
      lpProcName = (LPCSTR)((uint)pFVar2 & 0x7fffffff);
      if (-1 < (int)pFVar2) {
        lpProcName = lpProcName + (*(uint *)(param_1 + 0xc) ^ 0x49c042d1) + 2;
      }
      pFVar2 = GetProcAddress(hModule,lpProcName);
      *ppFVar4 = pFVar2;
    }
    piVar3 = piVar3 + 5;
    iVar1 = *piVar3;
  }
  return;
}



void FUN_01401e5c(void)

{
  FUN_01401e7c(&DAT_01415900);
  return;
}



void FUN_01401e66(void)

{
  FUN_0140241e((int *)&LAB_01401e72);
  return;
}



void __fastcall FUN_01401e7c(undefined4 *param_1)

{
  *(undefined *)(param_1 + 1) = 0;
  param_1[2] = 0;
  *param_1 = &PTR_FUN_0140f1f4;
  return;
}



undefined4 * __thiscall FUN_01401e8d(void *this,byte param_1)

{
  FUN_01401ea9((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0140250e((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_01401ea9(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0140f1f4;
  return;
}



int __thiscall FUN_01401eb0(void *this,LPCSTR param_1,int param_2)

{
  LSTATUS LVar1;
  void *local_c;
  DWORD local_8;
  
  if (*(char *)((int)this + 4) != '\0') {
    local_8 = 4;
    local_c = this;
    LVar1 = RegQueryValueExA(*(HKEY *)((int)this + 8),param_1,(LPDWORD)0x0,(LPDWORD)&param_1,
                             (LPBYTE)&local_c,&local_8);
    if ((LVar1 == 0) && (param_1 == (LPCSTR)0x4)) {
      param_2 = (int)local_c;
    }
  }
  return param_2;
}



undefined * __thiscall FUN_01401f16(void *this,LPCSTR param_1,undefined *param_2)

{
  LSTATUS LVar1;
  DWORD local_8;
  
  DAT_01415700 = 0;
  local_8 = 0x200;
  if (((*(char *)((int)this + 4) != '\0') &&
      (LVar1 = RegQueryValueExA(*(HKEY *)((int)this + 8),param_1,(LPDWORD)0x0,(LPDWORD)&param_1,
                                &DAT_01415700,&local_8), LVar1 == 0)) && (param_1 == (LPCSTR)0x1)) {
    param_2 = &DAT_01415700;
  }
  return param_2;
}



void __thiscall FUN_01401f62(void *this,LPCSTR param_1,BYTE *param_2)

{
  size_t sVar1;
  
  if (*(char *)((int)this + 4) != '\0') {
    sVar1 = _strlen((char *)param_2);
    RegSetValueExA(*(HKEY *)((int)this + 8),param_1,0,1,param_2,sVar1 + 1);
  }
  return;
}



void __fastcall FUN_01401f90(int param_1)

{
  char *pcVar1;
  LSTATUS LVar2;
  CHAR local_408 [1024];
  DWORD local_8;
  
  pcVar1 = FUN_01401fee();
  wsprintfA(local_408,s_Software_Valve__s_Settings__014115a0,pcVar1);
  LVar2 = RegCreateKeyExA((HKEY)0x80000001,local_408,0,(LPSTR)0x0,0,0xf003f,
                          (LPSECURITY_ATTRIBUTES)0x0,(PHKEY)(param_1 + 8),&local_8);
  if (LVar2 == 0) {
    *(undefined *)(param_1 + 4) = 1;
  }
  else {
    *(undefined *)(param_1 + 4) = 0;
  }
  return;
}



char * FUN_01401fee(void)

{
  return s_Half_Life_014115bc;
}



bool __cdecl FUN_01402008(byte *param_1)

{
  int iVar1;
  int local_28 [9];
  
  iVar1 = FUN_01404f29(param_1,local_28);
  return (bool)('\x01' - (iVar1 != 0));
}



uint __cdecl FUN_01402023(HKEY param_1,byte *param_2,byte *param_3)

{
  char cVar1;
  bool bVar2;
  uint *puVar3;
  size_t sVar4;
  uint uVar5;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined4 uVar6;
  char *this;
  
  puVar3 = FUN_01402e10((uint *)param_1,s__steam_014114e4);
  if (puVar3 != (uint *)0x0) {
    this = s__steam_014114e4;
    sVar4 = _strlen(s__steam_014114e4);
    cVar1 = *(char *)(sVar4 + (int)puVar3);
    uVar5 = CONCAT31((int3)((uint)(char *)(sVar4 + (int)puVar3) >> 8),cVar1);
    if ((cVar1 == '\0') || (uVar5 = FUN_014025ec(this,(int)cVar1), uVar5 != 0)) goto LAB_01402075;
  }
  bVar2 = FUN_01402008(param_3);
  uVar5 = CONCAT31(extraout_var,bVar2);
  if (!bVar2) {
    bVar2 = FUN_01402008(param_2);
    uVar5 = CONCAT31(extraout_var_00,bVar2);
    if (bVar2) {
      uVar6 = FUN_01402088(param_1);
      return CONCAT31((int3)((uint)uVar6 >> 8),1);
    }
  }
LAB_01402075:
  return uVar5 & 0xffffff00;
}



void __cdecl FUN_01402088(HKEY param_1)

{
  char cVar1;
  HMODULE hModule;
  char *pcVar2;
  LSTATUS LVar3;
  size_t sVar4;
  HWND hWnd;
  uint *puVar5;
  FILE *pFVar6;
  undefined4 *puVar7;
  BYTE *lpFilename;
  DWORD DVar8;
  BYTE local_32c [260];
  uint local_228 [65];
  undefined4 local_124;
  DWORD local_20;
  uint *local_1c;
  char *local_18;
  char *local_14;
  undefined4 local_10;
  DWORD local_c;
  HKEY local_8;
  
  lpFilename = local_32c;
  DVar8 = 0x104;
  hModule = GetModuleHandleA((LPCSTR)0x0);
  GetModuleFileNameA(hModule,(LPSTR)lpFilename,DVar8);
  pcVar2 = _strrchr((char *)local_32c,0x5c);
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  LVar3 = RegOpenKeyA((HKEY)0x80000001,s_Software_Valve_Steam_0141168c,&local_8);
  if (LVar3 == 0) {
    sVar4 = _strlen((char *)local_32c);
    RegSetValueExA(local_8,s_TempAppPath_01411680,0,1,local_32c,sVar4 + 1);
    sVar4 = _strlen((char *)param_1);
    RegSetValueExA(local_8,s_TempAppCmdLine_01411670,0,1,(BYTE *)param_1,sVar4 + 1);
    local_c = 0xffffffff;
    RegSetValueExA(local_8,s_TempAppID_01411664,0,4,(BYTE *)&local_c,4);
    RegCloseKey(local_8);
  }
  hWnd = FindWindowA(s_Valve_SteamIPC_Class_0141163c,s_Hidden_Window_01411654);
  if (hWnd == (HWND)0x0) {
    local_124._0_1_ = '\0';
    DVar8 = GetCurrentDirectoryA(0x104,(LPSTR)local_228);
    if (DVar8 != 0) {
      puVar5 = (uint *)_strrchr((char *)local_228,0x5c);
      while (puVar5 != (uint *)0x0) {
        *(undefined *)((int)puVar5 + 1) = 0;
        FUN_01402900(puVar5,(uint *)s_steam_dev_exe_0141162c);
        pFVar6 = (FILE *)FUN_014028a8((LPCSTR)local_228,&DAT_01411568);
        if (pFVar6 != (FILE *)0x0) {
LAB_014021ff:
          FUN_0140277d(pFVar6);
          FUN_014028f0(&local_124,local_228);
          break;
        }
        *(undefined *)((int)puVar5 + 1) = 0;
        FUN_01402900(puVar5,(uint *)s_steam_exe_01411620);
        pFVar6 = (FILE *)FUN_014028a8((LPCSTR)local_228,&DAT_01411568);
        if (pFVar6 != (FILE *)0x0) goto LAB_014021ff;
        *(undefined *)puVar5 = 0;
        puVar5 = (uint *)_strrchr((char *)local_228,0x5c);
      }
    }
    if ((char)local_124 == '\0') {
      LVar3 = RegOpenKeyA((HKEY)0x80000001,s_Software_Valve_Steam_0141168c,&param_1);
      if (LVar3 == 0) {
        local_c = 0x104;
        RegQueryValueExA(param_1,s_SteamExe_01411614,(LPDWORD)0x0,&local_20,(LPBYTE)&local_124,
                         &local_c);
        RegCloseKey(param_1);
      }
      if ((char)local_124 == '\0') {
        MessageBox((HWND)0x0,s_Error_running_game__could_not_fi_014115dc,s_Fatal_Error_01411260,0x10
                  );
        return;
      }
    }
    puVar7 = &local_124;
    cVar1 = (char)local_124;
    while (cVar1 != '\0') {
      if (*(char *)puVar7 == '/') {
        *(char *)puVar7 = '\\';
      }
      puVar7 = (undefined4 *)((int)puVar7 + 1);
      cVar1 = *(char *)puVar7;
    }
    FUN_014028f0(local_228,&local_124);
    pcVar2 = _strrchr((char *)local_228,0x5c);
    if (pcVar2 != (char *)0x0) {
      *pcVar2 = '\0';
      FUN_0140526b((LPCSTR)local_228);
    }
    local_1c = &local_124;
    local_18 = s__silent_014115d4;
    local_14 = s__applaunch_014115c8;
    local_10 = 0;
    FUN_01405254(1,&local_124,&local_1c);
  }
  else {
    PostMessageA(hWnd,0x403,0,0);
  }
  return;
}



int * __cdecl FUN_014023a0(int *param_1)

{
  SIZE_T SVar1;
  int **ppiVar2;
  
  execude_0xd();
  SVar1 = FUN_014058af((undefined *)DAT_01416ff0);
  if (SVar1 < (uint)((int)DAT_01416fec + (4 - (int)DAT_01416ff0))) {
    SVar1 = FUN_014058af((undefined *)DAT_01416ff0);
    ppiVar2 = FUN_01405580(DAT_01416ff0,(uint *)(SVar1 + 0x10));
    if (ppiVar2 == (int **)0x0) {
      param_1 = (int *)0x0;
      goto LAB_01402415;
    }
    DAT_01416fec = ppiVar2 + ((int)DAT_01416fec - (int)DAT_01416ff0 >> 2);
    DAT_01416ff0 = ppiVar2;
  }
  *DAT_01416fec = param_1;
  DAT_01416fec = DAT_01416fec + 1;
LAB_01402415:
  endCritical_0xd();
  return param_1;
}



int __cdecl FUN_0140241e(int *param_1)

{
  int *piVar1;
  
  piVar1 = FUN_014023a0(param_1);
  return (piVar1 != (int *)0x0) - 1;
}



void __fastcall FUN_0140245f(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0140f214;
  critical_code_area_executor(0x1b);
  if ((undefined *)param_1[1] != (undefined *)0x0) {
    FUN_01404c4e((undefined *)param_1[1]);
  }
  endCriticalFromID(0x1b);
  return;
}



undefined4 * __thiscall FUN_01402488(void *this,byte param_1)

{
  FUN_0140245f((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0140250e((undefined *)this);
  }
  return (undefined4 *)this;
}



void __cdecl FUN_0140250e(undefined *param_1)

{
  FUN_01404c4e(param_1);
  return;
}



uint __thiscall FUN_014025ec(void *this,int param_1)

{
  uint uVar1;
  
  if (1 < DAT_014139c4) {
    uVar1 = FUN_01405ac0(this,param_1,8);
    return uVar1;
  }
  return (byte)PTR_DAT_014137b8[param_1 * 2] & 8;
}



undefined4 __cdecl FUN_0140277d(FILE *param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0xffffffff;
  if ((*(byte *)&param_1->_flag & 0x40) == 0) {
    FUN_01405bf1((uint)param_1);
    uVar1 = __fclose_lk(param_1);
    FUN_01405c43((uint)param_1);
  }
  else {
    param_1->_flag = 0;
  }
  return uVar1;
}



// Library Function - Single Match
//  __fclose_lk
// 
// Library: Visual Studio 2003 Release

undefined4 __cdecl __fclose_lk(FILE *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  if ((*(byte *)&param_1->_flag & 0x83) != 0) {
    uVar2 = FUN_01405dfd((int *)param_1);
    __freebuf(param_1);
    iVar1 = FUN_01405c95(param_1->_file);
    if (iVar1 < 0) {
      uVar2 = 0xffffffff;
    }
    else if (param_1->_tmpfname != (char *)0x0) {
      FUN_01404c4e(param_1->_tmpfname);
      param_1->_tmpfname = (char *)0x0;
    }
  }
  param_1->_flag = 0;
  return uVar2;
}



uint __cdecl FUN_014027fa(byte **param_1)

{
  byte **ppbVar1;
  uint uVar2;
  
  FUN_01405bf1((uint)param_1);
  ppbVar1 = param_1 + 1;
  *ppbVar1 = *ppbVar1 + -1;
  if ((int)*ppbVar1 < 0) {
    uVar2 = FUN_01405f06(param_1);
  }
  else {
    uVar2 = (uint)**param_1;
    *param_1 = *param_1 + 1;
  }
  FUN_01405c43((uint)param_1);
  return uVar2;
}



int __cdecl FUN_01402836(byte *param_1)

{
  int iVar1;
  int iVar2;
  
  FUN_01405c20(1,0x14139f0);
  iVar1 = FUN_01405fe2((void **)&DAT_014139f0);
  iVar2 = FUN_01406099((char **)&DAT_014139f0,param_1,(undefined4 *)&stack0x00000008);
  FUN_0140606f(iVar1,(int *)&DAT_014139f0);
  FUN_01405c72(1,0x14139f0);
  return iVar2;
}



undefined4 * __cdecl FUN_01402877(LPCSTR param_1,char *param_2,uint param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar1 = FUN_01406a13();
  if (puVar1 == (undefined4 *)0x0) {
    return (undefined4 *)0x0;
  }
  puVar2 = FUN_014068a3(param_1,param_2,param_3,puVar1);
  FUN_01405c43((uint)puVar1);
  return puVar2;
}



void __cdecl FUN_014028a8(LPCSTR param_1,char *param_2)

{
  FUN_01402877(param_1,param_2,0x40);
  return;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_014028c0(undefined1 param_1)

{
  uint in_EAX;
  undefined1 *puVar1;
  undefined4 unaff_retaddr;
  
  puVar1 = &param_1;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = unaff_retaddr;
  return;
}



uint * __cdecl FUN_014028f0(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  uVar3 = (uint)param_2 & 3;
  puVar4 = param_1;
  while (uVar3 != 0) {
    bVar1 = *(byte *)param_2;
    uVar3 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_014029d8;
    *(byte *)puVar4 = bVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    uVar3 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar3 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar3 == '\0') {
LAB_014029d8:
        *(byte *)puVar4 = (byte)uVar3;
        return param_1;
      }
      if ((char)(uVar3 >> 8) == '\0') {
        *(short *)puVar4 = (short)uVar3;
        return param_1;
      }
      if ((uVar3 & 0xff0000) == 0) {
        *(short *)puVar4 = (short)uVar3;
        *(byte *)((int)puVar4 + 2) = 0;
        return param_1;
      }
      if ((uVar3 & 0xff000000) == 0) {
        *puVar4 = uVar3;
        return param_1;
      }
    }
    *puVar4 = uVar3;
    puVar4 = puVar4 + 1;
  } while( true );
}



uint * __cdecl FUN_01402900(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar4 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar4 != 0) {
    bVar1 = *(byte *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (bVar1 == 0) goto LAB_0140294f;
    uVar4 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar5 = puVar3;
      puVar3 = puVar5 + 1;
    } while (((*puVar5 ^ 0xffffffff ^ *puVar5 + 0x7efefeff) & 0x81010100) == 0);
    uVar4 = *puVar5;
    if ((char)uVar4 == '\0') goto LAB_01402961;
    if ((char)(uVar4 >> 8) == '\0') {
      puVar5 = (uint *)((int)puVar5 + 1);
      goto LAB_01402961;
    }
    if ((uVar4 & 0xff0000) == 0) {
      puVar5 = (uint *)((int)puVar5 + 2);
      goto LAB_01402961;
    }
  } while ((uVar4 & 0xff000000) != 0);
LAB_0140294f:
  puVar5 = (uint *)((int)puVar3 + -1);
LAB_01402961:
  uVar4 = (uint)param_2 & 3;
  while (uVar4 != 0) {
    bVar1 = *(byte *)param_2;
    uVar4 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_014029d8;
    *(byte *)puVar5 = bVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    uVar4 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar4 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar4 == '\0') {
LAB_014029d8:
        *(byte *)puVar5 = (byte)uVar4;
        return param_1;
      }
      if ((char)(uVar4 >> 8) == '\0') {
        *(short *)puVar5 = (short)uVar4;
        return param_1;
      }
      if ((uVar4 & 0xff0000) == 0) {
        *(short *)puVar5 = (short)uVar4;
        *(byte *)((int)puVar5 + 2) = 0;
        return param_1;
      }
      if ((uVar4 & 0xff000000) == 0) {
        *puVar5 = uVar4;
        return param_1;
      }
    }
    *puVar5 = uVar4;
    puVar5 = puVar5 + 1;
  } while( true );
}



// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2003 Release

void * __cdecl dynamische_Speicherallokation(uint Memory_size)

{
  void *Memory;
  
  Memory = malloc_mem(Memory_size,1);
  return Memory;
}



// Library Function - Single Match
//  _strlen
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

size_t __cdecl _strlen(char *_Str)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  uVar2 = (uint)_Str & 3;
  puVar3 = (uint *)_Str;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_01402a43;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (int)puVar4 - (int)_Str;
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (size_t)((int)puVar4 + (1 - (int)_Str));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (size_t)((int)puVar4 + (2 - (int)_Str));
    }
  } while ((uVar2 & 0xff000000) != 0);
LAB_01402a43:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void * __cdecl Initialize_Memory(void *_Dst,int _Val,size_t _Size)

{
  uint uVar1;
  uint uVar2;
  size_t sVar3;
  uint *puVar4;
  
  if (_Size == 0) {
    return _Dst;
  }
  uVar1 = _Val & 0xff;
  puVar4 = (uint *)_Dst;
  if (3 < _Size) {
    uVar2 = -(int)_Dst & 3;
    sVar3 = _Size;
    if (uVar2 != 0) {
      sVar3 = _Size - uVar2;
      do {
        *(undefined *)puVar4 = (undefined)_Val;
        puVar4 = (uint *)((int)puVar4 + 1);
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    _Size = sVar3 & 3;
    uVar2 = sVar3 >> 2;
    if (uVar2 != 0) {
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar4 = uVar1;
        puVar4 = puVar4 + 1;
      }
      if (_Size == 0) {
        return _Dst;
      }
    }
  }
  do {
    *(char *)puVar4 = (char)uVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    _Size = _Size - 1;
  } while (_Size != 0);
  return _Dst;
}



undefined4 * __cdecl FUN_01402ad0(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_01402c87_caseD_2;
        case 3:
          goto switchD_01402c87_caseD_3;
        }
        goto switchD_01402c87_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_01402c87_caseD_0;
      case 1:
        goto switchD_01402c87_caseD_1;
      case 2:
        goto switchD_01402c87_caseD_2;
      case 3:
        goto switchD_01402c87_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_01402c87_caseD_2;
            case 3:
              goto switchD_01402c87_caseD_3;
            }
            goto switchD_01402c87_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_01402c87_caseD_2;
            case 3:
              goto switchD_01402c87_caseD_3;
            }
            goto switchD_01402c87_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_01402c87_caseD_2;
            case 3:
              goto switchD_01402c87_caseD_3;
            }
            goto switchD_01402c87_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_01402c87_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_01402c87_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_01402c87_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_01402c87_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_01402b05_caseD_2;
      case 3:
        goto switchD_01402b05_caseD_3;
      }
      goto switchD_01402b05_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_01402b05_caseD_0;
    case 1:
      goto switchD_01402b05_caseD_1;
    case 2:
      goto switchD_01402b05_caseD_2;
    case 3:
      goto switchD_01402b05_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_01402b05_caseD_2;
          case 3:
            goto switchD_01402b05_caseD_3;
          }
          goto switchD_01402b05_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_01402b05_caseD_2;
          case 3:
            goto switchD_01402b05_caseD_3;
          }
          goto switchD_01402b05_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_01402b05_caseD_2;
          case 3:
            goto switchD_01402b05_caseD_3;
          }
          goto switchD_01402b05_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar1) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_01402b05_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_01402b05_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_01402b05_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_01402b05_caseD_0:
  return param_1;
}



uint * __cdecl FUN_01402e10(uint *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  char cVar6;
  uint uVar7;
  char *pcVar8;
  uint uVar9;
  uint *puVar10;
  
  cVar3 = *param_2;
  if (cVar3 == '\0') {
    return param_1;
  }
  if (param_2[1] == '\0') {
    uVar4 = (uint)param_1 & 3;
    while (uVar4 != 0) {
      if (*(char *)param_1 == cVar3) {
        return param_1;
      }
      if (*(char *)param_1 == '\0') {
        return (uint *)0x0;
      }
      uVar4 = (uint)(uint *)((int)param_1 + 1) & 3;
      param_1 = (uint *)((int)param_1 + 1);
    }
    while( true ) {
      while( true ) {
        uVar4 = *param_1;
        uVar9 = uVar4 ^ CONCAT22(CONCAT11(cVar3,cVar3),CONCAT11(cVar3,cVar3));
        uVar7 = uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff;
        puVar10 = param_1 + 1;
        if (((uVar9 ^ 0xffffffff ^ uVar9 + 0x7efefeff) & 0x81010100) != 0) break;
        param_1 = puVar10;
        if ((uVar7 & 0x81010100) != 0) {
          if ((uVar7 & 0x1010100) != 0) {
            return (uint *)0x0;
          }
          if ((uVar4 + 0x7efefeff & 0x80000000) == 0) {
            return (uint *)0x0;
          }
        }
      }
      uVar4 = *param_1;
      if ((char)uVar4 == cVar3) {
        return param_1;
      }
      if ((char)uVar4 == '\0') {
        return (uint *)0x0;
      }
      cVar6 = (char)(uVar4 >> 8);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 1);
      }
      if (cVar6 == '\0') break;
      cVar6 = (char)(uVar4 >> 0x10);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 2);
      }
      if (cVar6 == '\0') {
        return (uint *)0x0;
      }
      cVar6 = (char)(uVar4 >> 0x18);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 3);
      }
      param_1 = puVar10;
      if (cVar6 == '\0') {
        return (uint *)0x0;
      }
    }
    return (uint *)0x0;
  }
  do {
    cVar6 = *(char *)param_1;
    do {
      while (puVar10 = param_1, param_1 = (uint *)((int)puVar10 + 1), cVar6 != cVar3) {
        if (cVar6 == '\0') {
          return (uint *)0x0;
        }
        cVar6 = *(char *)param_1;
      }
      cVar6 = *(char *)param_1;
      pcVar8 = param_2;
      puVar5 = puVar10;
    } while (cVar6 != param_2[1]);
    do {
      if (pcVar8[2] == '\0') {
        return puVar10;
      }
      if (*(char *)(uint *)((int)puVar5 + 2) != pcVar8[2]) break;
      pcVar1 = pcVar8 + 3;
      if (*pcVar1 == '\0') {
        return puVar10;
      }
      pcVar2 = (char *)((int)puVar5 + 3);
      pcVar8 = pcVar8 + 2;
      puVar5 = (uint *)((int)puVar5 + 2);
    } while (*pcVar1 == *pcVar2);
  } while( true );
}



int __cdecl FUN_01402e90(char *param_1,int param_2,byte *param_3)

{
  int iVar1;
  char *local_24;
  int local_20;
  char *local_1c;
  undefined4 local_18;
  
  local_1c = param_1;
  local_24 = param_1;
  local_18 = 0x42;
  local_20 = param_2;
  iVar1 = FUN_01406099(&local_24,param_3,(undefined4 *)&stack0x00000010);
  local_20 = local_20 + -1;
  if (local_20 < 0) {
    FUN_01406adb(0,&local_24);
  }
  else {
    *local_24 = '\0';
  }
  return iVar1;
}



// Library Function - Single Match
//  _strcmp
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

int __cdecl _strcmp(char *_Str1,char *_Str2)

{
  undefined2 uVar1;
  undefined4 uVar2;
  byte bVar3;
  byte bVar4;
  bool bVar5;
  
  if (((uint)_Str1 & 3) != 0) {
    if (((uint)_Str1 & 1) != 0) {
      bVar4 = *_Str1;
      _Str1 = _Str1 + 1;
      bVar5 = bVar4 < (byte)*_Str2;
      if (bVar4 != *_Str2) goto LAB_01402f34;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_01402f00;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_01402f34;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_01402f34;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_01402f00:
  while( true ) {
    uVar2 = *(undefined4 *)_Str1;
    bVar4 = (byte)uVar2;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 0x10);
    bVar5 = bVar4 < ((byte *)_Str2)[2];
    if (bVar4 != ((byte *)_Str2)[2]) break;
    bVar3 = (byte)((uint)uVar2 >> 0x18);
    if (bVar4 == 0) {
      return 0;
    }
    bVar5 = bVar3 < ((byte *)_Str2)[3];
    if (bVar3 != ((byte *)_Str2)[3]) break;
    _Str2 = (char *)((byte *)_Str2 + 4);
    _Str1 = (char *)((int)_Str1 + 4);
    if (bVar3 == 0) {
      return 0;
    }
  }
LAB_01402f34:
  return (uint)bVar5 * -2 + 1;
}



// Library Function - Single Match
//  _strrchr
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strrchr(char *_Str,int _Ch)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  
  iVar2 = -1;
  do {
    pcVar4 = _Str;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar4 = _Str + 1;
    cVar1 = *_Str;
    _Str = pcVar4;
  } while (cVar1 != '\0');
  iVar2 = -(iVar2 + 1);
  pcVar4 = pcVar4 + -1;
  do {
    pcVar3 = pcVar4;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar3 = pcVar4 + -1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar3;
  } while ((char)_Ch != cVar1);
  pcVar3 = pcVar3 + 1;
  if (*pcVar3 != (char)_Ch) {
    pcVar3 = (char *)0x0;
  }
  return pcVar3;
}



HANDLE __cdecl FUN_01402fa7(LPCSTR param_1,uint *param_2)

{
  HANDLE pvVar1;
  DWORD DVar2;
  DWORD *pDVar3;
  uint uVar4;
  _WIN32_FIND_DATAA local_144;
  
  pvVar1 = FindFirstFileA(param_1,&local_144);
  if (pvVar1 != (HANDLE)0xffffffff) {
    *param_2 = -(uint)(local_144.dwFileAttributes != 0x80) & local_144.dwFileAttributes;
    uVar4 = ConvertFileTimeToTimeT(&local_144.ftCreationTime);
    param_2[1] = uVar4;
    uVar4 = ConvertFileTimeToTimeT(&local_144.ftLastAccessTime);
    param_2[2] = uVar4;
    uVar4 = ConvertFileTimeToTimeT(&local_144.ftLastWriteTime);
    param_2[3] = uVar4;
    param_2[4] = local_144.nFileSizeLow;
    FUN_014028f0(param_2 + 5,(uint *)local_144.cFileName);
    return pvVar1;
  }
  DVar2 = GetLastError();
  if (DVar2 < 2) {
LAB_01402fe5:
    pDVar3 = FUN_01406c66();
    *pDVar3 = 0x16;
  }
  else {
    if (3 < DVar2) {
      if (DVar2 == 8) {
        pDVar3 = FUN_01406c66();
        *pDVar3 = 0xc;
        return (HANDLE)0xffffffff;
      }
      if (DVar2 != 0x12) goto LAB_01402fe5;
    }
    pDVar3 = FUN_01406c66();
    *pDVar3 = 2;
  }
  return (HANDLE)0xffffffff;
}



undefined4 __cdecl FUN_01403074(HANDLE param_1,uint *param_2)

{
  BOOL BVar1;
  DWORD DVar2;
  DWORD *pDVar3;
  uint uVar4;
  _WIN32_FIND_DATAA local_144;
  
  BVar1 = FindNextFileA(param_1,&local_144);
  if (BVar1 != 0) {
    *param_2 = -(uint)(local_144.dwFileAttributes != 0x80) & local_144.dwFileAttributes;
    uVar4 = ConvertFileTimeToTimeT(&local_144.ftCreationTime);
    param_2[1] = uVar4;
    uVar4 = ConvertFileTimeToTimeT(&local_144.ftLastAccessTime);
    param_2[2] = uVar4;
    uVar4 = ConvertFileTimeToTimeT(&local_144.ftLastWriteTime);
    param_2[3] = uVar4;
    param_2[4] = local_144.nFileSizeLow;
    FUN_014028f0(param_2 + 5,(uint *)local_144.cFileName);
    return 0;
  }
  DVar2 = GetLastError();
  if (DVar2 < 2) {
LAB_014030ae:
    pDVar3 = FUN_01406c66();
    *pDVar3 = 0x16;
  }
  else {
    if (3 < DVar2) {
      if (DVar2 == 8) {
        pDVar3 = FUN_01406c66();
        *pDVar3 = 0xc;
        return 0xffffffff;
      }
      if (DVar2 != 0x12) goto LAB_014030ae;
    }
    pDVar3 = FUN_01406c66();
    *pDVar3 = 2;
  }
  return 0xffffffff;
}



undefined4 __cdecl FUN_0140313c(HANDLE param_1)

{
  BOOL BVar1;
  DWORD *pDVar2;
  
  BVar1 = FindClose(param_1);
  if (BVar1 == 0) {
    pDVar2 = FUN_01406c66();
    *pDVar2 = 0x16;
    return 0xffffffff;
  }
  return 0;
}



// Library Function - Single Match
//  ___timet_from_ft
// 
// Library: Visual Studio 2003 Release

int __cdecl ConvertFileTimeToTimeT(FILETIME *pFileTime)

{
  BOOL bConversionStatus;
  int iTimeT;
  _SYSTEMTIME systemTime;
  _FILETIME localFileTime;
  
  if ((pFileTime->dwLowDateTime != 0) || (pFileTime->dwHighDateTime != 0)) {
    bConversionStatus = FileTimeToLocalFileTime(pFileTime,&localFileTime);
    if (bConversionStatus != 0) {
      bConversionStatus = FileTimeToSystemTime(&localFileTime,&systemTime);
      if (bConversionStatus != 0) {
        iTimeT = ConvertSystemTimeToTimeT
                           ((uint)systemTime.wYear,(uint)systemTime.wMonth,(uint)systemTime.wDay,
                            (uint)systemTime.wHour,(uint)systemTime.wMinute,(uint)systemTime.wSecond
                            ,-1);
        return iTimeT;
      }
    }
  }
  return -1;
}



uint * __cdecl FUN_014031d0(uint *param_1,char param_2)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar1 = (uint)param_1 & 3;
  while (uVar1 != 0) {
    if (*(char *)param_1 == param_2) {
      return param_1;
    }
    if (*(char *)param_1 == '\0') {
      return (uint *)0x0;
    }
    uVar1 = (uint)(uint *)((int)param_1 + 1) & 3;
    param_1 = (uint *)((int)param_1 + 1);
  }
  while( true ) {
    while( true ) {
      uVar1 = *param_1;
      uVar4 = uVar1 ^ CONCAT22(CONCAT11(param_2,param_2),CONCAT11(param_2,param_2));
      uVar3 = uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff;
      puVar5 = param_1 + 1;
      if (((uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff) & 0x81010100) != 0) break;
      param_1 = puVar5;
      if ((uVar3 & 0x81010100) != 0) {
        if ((uVar3 & 0x1010100) != 0) {
          return (uint *)0x0;
        }
        if ((uVar1 + 0x7efefeff & 0x80000000) == 0) {
          return (uint *)0x0;
        }
      }
    }
    uVar1 = *param_1;
    if ((char)uVar1 == param_2) {
      return param_1;
    }
    if ((char)uVar1 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 8);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar1 >> 0x10);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 2);
    }
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 0x18);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 3);
    }
    param_1 = puVar5;
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
  }
  return (uint *)0x0;
}



int __cdecl FUN_0140328c(char *param_1,byte *param_2)

{
  int iVar1;
  char *local_24;
  int local_20;
  char *local_1c;
  undefined4 local_18;
  
  local_1c = param_1;
  local_24 = param_1;
  local_18 = 0x42;
  local_20 = 0x7fffffff;
  iVar1 = FUN_01406099(&local_24,param_2,(undefined4 *)&stack0x0000000c);
  local_20 = local_20 + -1;
  if (local_20 < 0) {
    FUN_01406adb(0,&local_24);
  }
  else {
    *local_24 = '\0';
  }
  return iVar1;
}



undefined4 __cdecl FUN_014032fd(uint param_1)

{
  int iVar1;
  undefined **ppuVar2;
  uint uVar3;
  
  uVar3 = param_1;
  if (DAT_01415fc8 == 3) {
    if (param_1 < 0x3f9) {
      DAT_01417018 = param_1;
      return 1;
    }
  }
  else if (DAT_01415fc8 == 2) {
    uVar3 = param_1 + 0xf & 0xfffffff0;
    if (uVar3 < 0x781) {
      DAT_014136e4 = uVar3;
      return 1;
    }
  }
  else if ((DAT_01415fc8 == 1) && (param_1 != 0)) {
    FUN_01406d3a(&param_1);
    if ((byte)param_1 < 6) {
      uVar3 = uVar3 + 0xf & 0xfffffff0;
      if ((uVar3 < 0x781) && (ppuVar2 = FUN_01404319(), ppuVar2 != (undefined **)0x0)) {
        DAT_014136e4 = uVar3;
        DAT_01415fc8 = 2;
        return 1;
      }
    }
    else if ((uVar3 < 0x3f9) && (iVar1 = FUN_014033b0(uVar3), iVar1 != 0)) {
      DAT_01415fc8 = 3;
      DAT_01417018 = uVar3;
      return 1;
    }
  }
  return 0;
}



undefined4 __cdecl FUN_014033b0(undefined4 param_1)

{
  DAT_01417014 = HeapAlloc(DAT_01415fc4,0,0x140);
  if (DAT_01417014 == (LPVOID)0x0) {
    return 0;
  }
  DAT_0141700c = 0;
  DAT_01417010 = 0;
  DAT_01417004 = DAT_01417014;
  DAT_01417018 = param_1;
  DAT_01416ffc = 0x10;
  return 1;
}



uint __cdecl FUN_014033f8(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_01417014;
  while( true ) {
    if (DAT_01417014 + DAT_01417010 * 0x14 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



void __cdecl FUN_01403423(uint *param_1,int param_2)

{
  char *pcVar1;
  uint *puVar2;
  int *piVar3;
  char cVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint *puVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  uint local_8;
  
  uVar5 = param_1[4];
  puVar12 = (uint *)(param_2 + -4);
  uVar14 = param_2 - param_1[3] >> 0xf;
  piVar3 = (int *)(uVar14 * 0x204 + 0x144 + uVar5);
  uVar13 = *puVar12;
  local_8 = uVar13 - 1;
  if ((local_8 & 1) == 0) {
    uVar6 = *(uint *)(local_8 + (int)puVar12);
    uVar7 = *(uint *)(param_2 + -8);
    if ((uVar6 & 1) == 0) {
      uVar9 = ((int)uVar6 >> 4) - 1;
      if (0x3f < uVar9) {
        uVar9 = 0x3f;
      }
      if (*(int *)((int)puVar12 + uVar13 + 3) == *(int *)((int)puVar12 + uVar13 + 7)) {
        if (uVar9 < 0x20) {
          pcVar1 = (char *)(uVar9 + 4 + uVar5);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 & 0x1f));
          puVar10 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 & uVar9;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar9;
          }
        }
        else {
          pcVar1 = (char *)(uVar9 + 4 + uVar5);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 - 0x20 & 0x1f));
          puVar10 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 & uVar9;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar9;
          }
        }
      }
      local_8 = local_8 + uVar6;
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 7) + 4) =
           *(undefined4 *)((int)puVar12 + uVar13 + 3);
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 3) + 8) =
           *(undefined4 *)((int)puVar12 + uVar13 + 7);
    }
    puVar10 = (uint *)(((int)local_8 >> 4) - 1);
    if ((uint *)0x3f < puVar10) {
      puVar10 = (uint *)0x3f;
    }
    puVar11 = param_1;
    if ((uVar7 & 1) == 0) {
      puVar12 = (uint *)((int)puVar12 - uVar7);
      puVar11 = (uint *)(((int)uVar7 >> 4) - 1);
      if ((uint *)0x3f < puVar11) {
        puVar11 = (uint *)0x3f;
      }
      local_8 = local_8 + uVar7;
      puVar10 = (uint *)(((int)local_8 >> 4) - 1);
      if ((uint *)0x3f < puVar10) {
        puVar10 = (uint *)0x3f;
      }
      if (puVar11 != puVar10) {
        if (puVar12[1] == puVar12[2]) {
          if (puVar11 < (uint *)0x20) {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 & 0x1f));
            puVar2 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
            *puVar2 = *puVar2 & uVar13;
            pcVar1 = (char *)((int)puVar11 + uVar5 + 4);
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              *param_1 = *param_1 & uVar13;
            }
          }
          else {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 - 0x20 & 0x1f));
            puVar2 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
            *puVar2 = *puVar2 & uVar13;
            pcVar1 = (char *)((int)puVar11 + uVar5 + 4);
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              param_1[1] = param_1[1] & uVar13;
            }
          }
        }
        *(uint *)(puVar12[2] + 4) = puVar12[1];
        *(uint *)(puVar12[1] + 8) = puVar12[2];
      }
    }
    if (((uVar7 & 1) != 0) || (puVar11 != puVar10)) {
      puVar12[1] = piVar3[(int)puVar10 * 2 + 1];
      puVar12[2] = (uint)(piVar3 + (int)puVar10 * 2);
      (piVar3 + (int)puVar10 * 2)[1] = (int)puVar12;
      *(uint **)(puVar12[1] + 8) = puVar12;
      if (puVar12[1] == puVar12[2]) {
        cVar4 = *(char *)((int)puVar10 + uVar5 + 4);
        *(char *)((int)puVar10 + uVar5 + 4) = cVar4 + '\x01';
        bVar8 = (byte)puVar10;
        if (puVar10 < (uint *)0x20) {
          if (cVar4 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
          }
          puVar10 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 & 0x1f);
        }
        else {
          if (cVar4 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
          }
          puVar10 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
      }
    }
    *puVar12 = local_8;
    *(uint *)((local_8 - 4) + (int)puVar12) = local_8;
    *piVar3 = *piVar3 + -1;
    if (*piVar3 == 0) {
      if (DAT_0141700c != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_01417000 * 0x8000 + DAT_0141700c[3]),0x8000,0x4000);
        DAT_0141700c[2] = DAT_0141700c[2] | 0x80000000U >> ((byte)DAT_01417000 & 0x1f);
        *(undefined4 *)(DAT_0141700c[4] + 0xc4 + DAT_01417000 * 4) = 0;
        *(char *)(DAT_0141700c[4] + 0x43) = *(char *)(DAT_0141700c[4] + 0x43) + -1;
        if (*(char *)(DAT_0141700c[4] + 0x43) == '\0') {
          DAT_0141700c[1] = DAT_0141700c[1] & 0xfffffffe;
        }
        if (DAT_0141700c[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_0141700c[3],0,0x8000);
          HeapFree(DAT_01415fc4,0,(LPVOID)DAT_0141700c[4]);
          FUN_01406fc0(DAT_0141700c,DAT_0141700c + 5,
                       (DAT_01417010 * 0x14 - (int)DAT_0141700c) + -0x14 + DAT_01417014);
          DAT_01417010 = DAT_01417010 + -1;
          if (DAT_0141700c < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_01417004 = DAT_01417014;
        }
      }
      DAT_0141700c = param_1;
      DAT_01417000 = uVar14;
    }
  }
  return;
}



int * __cdecl Allocate_Memory(uint *pRequestedSize)

{
  char *pcVar1;
  int *piVar2;
  char cVar3;
  int *piVar4;
  byte bVar5;
  uint uVar6;
  int iVar;
  uint *puVar;
  int iVar7;
  uint uVar8;
  int *piVar9;
  uint *puVar10;
  uint *puVar11;
  int iVar12;
  uint local_10;
  uint local_c;
  int local_8;
  
  puVar = DAT_01417014 + DAT_01417010 * 5;
  uVar6 = (int)pRequestedSize + 0x17U & 0xfffffff0;
  iVar = ((int)((int)pRequestedSize + 0x17U) >> 4) + -1;
  bVar5 = (byte)iVar;
  if (iVar < 0x20) {
    local_10 = 0xffffffff >> (bVar5 & 0x1f);
    local_c = 0xffffffff;
  }
  else {
    local_c = 0xffffffff >> (bVar5 - 0x20 & 0x1f);
    local_10 = 0;
  }
  pRequestedSize = DAT_01417004;
  if (DAT_01417004 < puVar) {
    do {
      if ((pRequestedSize[1] & local_c | *pRequestedSize & local_10) != 0) break;
      pRequestedSize = pRequestedSize + 5;
    } while (pRequestedSize < puVar);
  }
  puVar10 = DAT_01417014;
  if (pRequestedSize == puVar) {
    for (; (puVar10 < DAT_01417004 && ((puVar10[1] & local_c | *puVar10 & local_10) == 0));
        puVar10 = puVar10 + 5) {
    }
    pRequestedSize = puVar10;
    if (puVar10 == DAT_01417004) {
      for (; (puVar10 < puVar && (puVar10[2] == 0)); puVar10 = puVar10 + 5) {
      }
      puVar11 = DAT_01417014;
      pRequestedSize = puVar10;
      if (puVar10 == puVar) {
        for (; (puVar11 < DAT_01417004 && (puVar11[2] == 0)); puVar11 = puVar11 + 5) {
        }
        pRequestedSize = puVar11;
        if ((puVar11 == DAT_01417004) &&
           (pRequestedSize = Allocate_Memory_Block(), pRequestedSize == (uint *)0x0)) {
          return (int *)0x0;
        }
      }
      iVar = Allocate_Memory_Block((int)pRequestedSize);
      *(int *)pRequestedSize[4] = iVar;
      if (*(int *)pRequestedSize[4] == -1) {
        return (int *)0x0;
      }
    }
  }
  piVar4 = (int *)pRequestedSize[4];
  local_8 = *piVar4;
  if ((local_8 == -1) ||
     ((piVar4[local_8 + 0x31] & local_c | piVar4[local_8 + 0x11] & local_10) == 0)) {
    local_8 = 0;
    puVar = (uint *)(piVar4 + 0x11);
    uVar8 = piVar4[0x31] & local_c | piVar4[0x11] & local_10;
    while (uVar8 == 0) {
      puVar10 = puVar + 0x21;
      local_8 = local_8 + 1;
      puVar = puVar + 1;
      uVar8 = *puVar10 & local_c | local_10 & *puVar;
    }
  }
  iVar = 0;
  piVar2 = piVar4 + local_8 * 0x81 + 0x51;
  local_10 = piVar4[local_8 + 0x11] & local_10;
  if (local_10 == 0) {
    local_10 = piVar4[local_8 + 0x31] & local_c;
    iVar = 0x20;
  }
  for (; -1 < (int)local_10; local_10 = local_10 << 1) {
    iVar = iVar + 1;
  }
  piVar9 = (int *)piVar2[iVar * 2 + 1];
  iVar7 = *piVar9 - uVar6;
  iVar12 = (iVar7 >> 4) + -1;
  if (0x3f < iVar12) {
    iVar12 = 0x3f;
  }
  DAT_01417004 = pRequestedSize;
  if (iVar12 != iVar) {
    if (piVar9[1] == piVar9[2]) {
      if (iVar < 0x20) {
        pcVar1 = (char *)((int)piVar4 + iVar + 4);
        uVar8 = ~(0x80000000U >> ((byte)iVar & 0x1f));
        piVar4[local_8 + 0x11] = uVar8 & piVar4[local_8 + 0x11];
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *pRequestedSize = *pRequestedSize & uVar8;
        }
      }
      else {
        pcVar1 = (char *)((int)piVar4 + iVar + 4);
        uVar8 = ~(0x80000000U >> ((byte)iVar - 0x20 & 0x1f));
        piVar4[local_8 + 0x31] = piVar4[local_8 + 0x31] & uVar8;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          pRequestedSize[1] = pRequestedSize[1] & uVar8;
        }
      }
    }
    *(int *)(piVar9[2] + 4) = piVar9[1];
    *(int *)(piVar9[1] + 8) = piVar9[2];
    if (iVar7 == 0) goto LAB_01403a12;
    piVar9[1] = piVar2[iVar12 * 2 + 1];
    piVar9[2] = (int)(piVar2 + iVar12 * 2);
    (piVar2 + iVar12 * 2)[1] = (int)piVar9;
    *(int **)(piVar9[1] + 8) = piVar9;
    if (piVar9[1] == piVar9[2]) {
      cVar3 = *(char *)(iVar12 + 4 + (int)piVar4);
      bVar5 = (byte)iVar12;
      if (iVar12 < 0x20) {
        *(char *)(iVar12 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          *pRequestedSize = *pRequestedSize | 0x80000000U >> (bVar5 & 0x1f);
        }
        piVar4[local_8 + 0x11] = piVar4[local_8 + 0x11] | 0x80000000U >> (bVar5 & 0x1f);
      }
      else {
        *(char *)(iVar12 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          pRequestedSize[1] = pRequestedSize[1] | 0x80000000U >> (bVar5 - 0x20 & 0x1f);
        }
        piVar4[local_8 + 0x31] = piVar4[local_8 + 0x31] | 0x80000000U >> (bVar5 - 0x20 & 0x1f);
      }
    }
  }
  if (iVar7 != 0) {
    *piVar9 = iVar7;
    *(int *)(iVar7 + -4 + (int)piVar9) = iVar7;
  }
LAB_01403a12:
  piVar9 = (int *)((int)piVar9 + iVar7);
  *piVar9 = uVar6 + 1;
  *(uint *)((int)piVar9 + (uVar6 - 4)) = uVar6 + 1;
  iVar = *piVar2;
  *piVar2 = iVar + 1;
  if (((iVar == 0) && (pRequestedSize == DAT_0141700c)) && (local_8 == DAT_01417000)) {
    DAT_0141700c = (uint *)0x0;
  }
  *piVar4 = local_8;
  return piVar9 + 1;
}



undefined4 * Allocate_Memory_Block(void)

{
  LPVOID pHeapMemory;
  undefined4 *pMemoryBlock;
  
  if (DAT_01417010 == DAT_01416ffc) {
    pHeapMemory = HeapReAlloc(DAT_01415fc4,0,DAT_01417014,(DAT_01416ffc * 5 + 0x50) * 4);
    if (pHeapMemory == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_01416ffc = DAT_01416ffc + 0x10;
    DAT_01417014 = pHeapMemory;
  }
  pMemoryBlock = (undefined4 *)((int)DAT_01417014 + DAT_01417010 * 0x14);
  pHeapMemory = HeapAlloc(DAT_01415fc4,8,0x41c4);
  pMemoryBlock[4] = pHeapMemory;
  if (pHeapMemory != (LPVOID)0x0) {
    pHeapMemory = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    pMemoryBlock[3] = pHeapMemory;
    if (pHeapMemory != (LPVOID)0x0) {
      pMemoryBlock[2] = 0xffffffff;
      *pMemoryBlock = 0;
      pMemoryBlock[1] = 0;
      DAT_01417010 = DAT_01417010 + 1;
      *(undefined4 *)pMemoryBlock[4] = 0xffffffff;
      return pMemoryBlock;
    }
    HeapFree(DAT_01415fc4,0,(LPVOID)pMemoryBlock[4]);
  }
  return (undefined4 *)0x0;
}



int __cdecl Allocate_Memory_Block(int iMemoryBlockIndex)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  LPVOID pVirtualMemory;
  int *piVar6;
  int iVar7;
  int iVar8;
  int *pMemoryAddress;
  
  iVar3 = *(int *)(iMemoryBlockIndex + 0x10);
  iVar8 = 0;
  for (iVar4 = *(int *)(iMemoryBlockIndex + 8); -1 < iVar4; iVar4 = iVar4 << 1) {
    iVar8 = iVar8 + 1;
  }
  iVar7 = 0x3f;
  iVar4 = iVar8 * 0x204 + 0x144 + iVar3;
  iVar5 = iVar4;
  do {
    *(int *)(iVar5 + 8) = iVar5;
    *(int *)(iVar5 + 4) = iVar5;
    iVar5 = iVar5 + 8;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  pMemoryAddress = (int *)(iVar8 * 0x8000 + *(int *)(iMemoryBlockIndex + 0xc));
  pVirtualMemory = VirtualAlloc(pMemoryAddress,0x8000,0x1000,4);
  if (pVirtualMemory == (LPVOID)0x0) {
    iVar8 = -1;
  }
  else {
    if (pMemoryAddress <= pMemoryAddress + 0x1c00) {
      piVar6 = pMemoryAddress + 4;
      do {
        piVar6[-2] = -1;
        piVar6[0x3fb] = -1;
        piVar6[-1] = 0xff0;
        *piVar6 = (int)(piVar6 + 0x3ff);
        piVar6[1] = (int)(piVar6 + -0x401);
        piVar6[0x3fa] = 0xff0;
        piVar1 = piVar6 + 0x3fc;
        piVar6 = piVar6 + 0x400;
      } while (piVar1 <= pMemoryAddress + 0x1c00);
    }
    *(int **)(iVar4 + 0x1fc) = pMemoryAddress + 3;
    pMemoryAddress[5] = iVar4 + 0x1f8;
    *(int **)(iVar4 + 0x200) = pMemoryAddress + 0x1c03;
    pMemoryAddress[0x1c04] = iVar4 + 0x1f8;
    *(undefined4 *)(iVar3 + 0x44 + iVar8 * 4) = 0;
    *(undefined4 *)(iVar3 + 0xc4 + iVar8 * 4) = 1;
    cVar2 = *(char *)(iVar3 + 0x43);
    *(char *)(iVar3 + 0x43) = cVar2 + '\x01';
    if (cVar2 == '\0') {
      *(uint *)(iMemoryBlockIndex + 4) = *(uint *)(iMemoryBlockIndex + 4) | 1;
    }
    *(uint *)(iMemoryBlockIndex + 8) =
         *(uint *)(iMemoryBlockIndex + 8) & ~(0x80000000U >> ((byte)iVar8 & 0x1f));
  }
  return iVar8;
}



undefined4 __cdecl FUN_01403c01(uint *param_1,int param_2,int param_3)

{
  char *pcVar1;
  int *piVar2;
  int iVar3;
  char cVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  byte bVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint local_c;
  
  uVar5 = param_1[4];
  uVar12 = param_3 + 0x17U & 0xfffffff0;
  uVar10 = param_2 - param_1[3] >> 0xf;
  iVar3 = uVar10 * 0x204 + 0x144 + uVar5;
  iVar6 = *(int *)(param_2 + -4);
  iVar9 = iVar6 + -1;
  uVar13 = *(uint *)(iVar6 + -5 + param_2);
  iVar6 = iVar6 + -5 + param_2;
  if (iVar9 < (int)uVar12) {
    if (((uVar13 & 1) != 0) || ((int)(uVar13 + iVar9) < (int)uVar12)) {
      return 0;
    }
    local_c = ((int)uVar13 >> 4) - 1;
    if (0x3f < local_c) {
      local_c = 0x3f;
    }
    if (*(int *)(iVar6 + 4) == *(int *)(iVar6 + 8)) {
      if (local_c < 0x20) {
        pcVar1 = (char *)(local_c + 4 + uVar5);
        uVar11 = ~(0x80000000U >> ((byte)local_c & 0x1f));
        puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
        *puVar7 = *puVar7 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)(local_c + 4 + uVar5);
        uVar11 = ~(0x80000000U >> ((byte)local_c - 0x20 & 0x1f));
        puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
        *puVar7 = *puVar7 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(undefined4 *)(*(int *)(iVar6 + 8) + 4) = *(undefined4 *)(iVar6 + 4);
    *(undefined4 *)(*(int *)(iVar6 + 4) + 8) = *(undefined4 *)(iVar6 + 8);
    iVar6 = uVar13 + (iVar9 - uVar12);
    if (0 < iVar6) {
      uVar13 = (iVar6 >> 4) - 1;
      iVar9 = param_2 + -4 + uVar12;
      if (0x3f < uVar13) {
        uVar13 = 0x3f;
      }
      iVar3 = iVar3 + uVar13 * 8;
      *(undefined4 *)(iVar9 + 4) = *(undefined4 *)(iVar3 + 4);
      *(int *)(iVar9 + 8) = iVar3;
      *(int *)(iVar3 + 4) = iVar9;
      *(int *)(*(int *)(iVar9 + 4) + 8) = iVar9;
      if (*(int *)(iVar9 + 4) == *(int *)(iVar9 + 8)) {
        cVar4 = *(char *)(uVar13 + 4 + uVar5);
        *(char *)(uVar13 + 4 + uVar5) = cVar4 + '\x01';
        bVar8 = (byte)uVar13;
        if (uVar13 < 0x20) {
          if (cVar4 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
          }
          puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
        }
        else {
          if (cVar4 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
          }
          puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
          bVar8 = bVar8 - 0x20;
        }
        *puVar7 = *puVar7 | 0x80000000U >> (bVar8 & 0x1f);
      }
      piVar2 = (int *)(param_2 + -4 + uVar12);
      *piVar2 = iVar6;
      *(int *)(iVar6 + -4 + (int)piVar2) = iVar6;
    }
    *(uint *)(param_2 + -4) = uVar12 + 1;
    *(uint *)(param_2 + -8 + uVar12) = uVar12 + 1;
  }
  else if ((int)uVar12 < iVar9) {
    param_3 = iVar9 - uVar12;
    *(uint *)(param_2 + -4) = uVar12 + 1;
    piVar2 = (int *)(param_2 + -4 + uVar12);
    uVar11 = (param_3 >> 4) - 1;
    piVar2[-1] = uVar12 + 1;
    if (0x3f < uVar11) {
      uVar11 = 0x3f;
    }
    if ((uVar13 & 1) == 0) {
      uVar12 = ((int)uVar13 >> 4) - 1;
      if (0x3f < uVar12) {
        uVar12 = 0x3f;
      }
      if (*(int *)(iVar6 + 4) == *(int *)(iVar6 + 8)) {
        if (uVar12 < 0x20) {
          pcVar1 = (char *)(uVar12 + 4 + uVar5);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 & 0x1f));
          puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
          *puVar7 = *puVar7 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar12;
          }
        }
        else {
          pcVar1 = (char *)(uVar12 + 4 + uVar5);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 - 0x20 & 0x1f));
          puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
          *puVar7 = *puVar7 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar12;
          }
        }
      }
      *(undefined4 *)(*(int *)(iVar6 + 8) + 4) = *(undefined4 *)(iVar6 + 4);
      *(undefined4 *)(*(int *)(iVar6 + 4) + 8) = *(undefined4 *)(iVar6 + 8);
      param_3 = param_3 + uVar13;
      uVar11 = (param_3 >> 4) - 1;
      if (0x3f < uVar11) {
        uVar11 = 0x3f;
      }
    }
    iVar6 = iVar3 + uVar11 * 8;
    piVar2[1] = *(int *)(iVar3 + 4 + uVar11 * 8);
    piVar2[2] = iVar6;
    *(int **)(iVar6 + 4) = piVar2;
    *(int **)(piVar2[1] + 8) = piVar2;
    if (piVar2[1] == piVar2[2]) {
      cVar4 = *(char *)(uVar11 + 4 + uVar5);
      *(char *)(uVar11 + 4 + uVar5) = cVar4 + '\x01';
      bVar8 = (byte)uVar11;
      if (uVar11 < 0x20) {
        if (cVar4 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
        }
        puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
      }
      else {
        if (cVar4 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
        puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
        bVar8 = bVar8 - 0x20;
      }
      *puVar7 = *puVar7 | 0x80000000U >> (bVar8 & 0x1f);
    }
    *piVar2 = param_3;
    *(int *)(param_3 + -4 + (int)piVar2) = param_3;
  }
  return 1;
}



undefined4 FUN_01403fc8(void)

{
  LPVOID lp;
  BOOL BVar1;
  undefined4 uVar2;
  int iVar3;
  int **ppiVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  int **ppiVar8;
  int **ppiVar9;
  uint *puVar10;
  uint *puVar11;
  int **ppiVar12;
  int *piVar13;
  bool bVar14;
  int local_140 [64];
  uint *local_40;
  uint *local_3c;
  int **local_38;
  int local_34;
  uint local_30;
  int **local_2c;
  uint local_28;
  int local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  int local_14;
  int **local_10;
  int local_c;
  int *local_8;
  
  BVar1 = IsBadWritePtr(DAT_01417014,DAT_01417010 * 0x14);
  if (BVar1 == 0) {
    local_24 = 0;
    puVar10 = DAT_01417014;
    if (0 < DAT_01417010) {
      do {
        lp = (LPVOID)puVar10[4];
        local_3c = puVar10;
        BVar1 = IsBadWritePtr(lp,0x41c4);
        if (BVar1 != 0) {
          return 0xfffffffe;
        }
        local_10 = (int **)puVar10[3];
        local_30 = 0;
        local_2c = (int **)((int)lp + 0x144);
        local_18 = puVar10[2];
        puVar11 = (uint *)((int)lp + 0xc4);
        local_1c = 0;
        local_34 = 0;
        do {
          local_28 = 0;
          local_20 = 0;
          local_8 = (int *)0x0;
          bVar14 = -1 < (int)local_18;
          piVar13 = local_140;
          local_40 = puVar11;
          for (iVar6 = 0x40; iVar6 != 0; iVar6 = iVar6 + -1) {
            *piVar13 = 0;
            piVar13 = piVar13 + 1;
          }
          if (bVar14) {
            BVar1 = IsBadWritePtr(local_10,0x8000);
            if (BVar1 != 0) {
              return 0xfffffffc;
            }
            iVar6 = 0;
            ppiVar9 = local_10 + 0x3ff;
            do {
              ppiVar12 = ppiVar9 + -0x3fc;
              if ((ppiVar9[-0x3fd] != (int *)0xffffffff) || (*ppiVar9 != (int *)0xffffffff)) {
                return 0xfffffffb;
              }
              do {
                piVar13 = *ppiVar12;
                if (((uint)piVar13 & 1) == 0) {
                  iVar3 = ((int)piVar13 >> 4) + -1;
                  if (0x3f < iVar3) {
                    iVar3 = 0x3f;
                  }
                  local_140[iVar3] = local_140[iVar3] + 1;
                  piVar7 = piVar13;
                }
                else {
                  if (0x400 < (int)(int *)((int)piVar13 + -1)) {
                    return 0xfffffffa;
                  }
                  local_8 = (int *)((int)local_8 + 1);
                  piVar7 = (int *)((int)piVar13 + -1);
                }
                if ((((int)piVar7 < 0x10) || (((uint)piVar7 & 0xf) != 0)) || (0xff0 < (int)piVar7))
                {
                  return 0xfffffff9;
                }
                ppiVar4 = (int **)((int)(piVar7 + -1) + (int)ppiVar12);
                ppiVar12 = (int **)((int)piVar7 + (int)ppiVar12);
                if (*ppiVar4 != piVar13) {
                  return 0xfffffff8;
                }
              } while (ppiVar12 < ppiVar9);
              if (ppiVar12 != ppiVar9) {
                return 0xfffffff8;
              }
              ppiVar9 = ppiVar9 + 0x400;
              iVar6 = iVar6 + 1;
            } while (iVar6 < 8);
            if (*local_2c != local_8) {
              return 0xfffffff7;
            }
            local_c = 0;
            local_8 = local_140;
            ppiVar9 = local_2c;
            do {
              local_14 = 0;
              ppiVar12 = (int **)ppiVar9[1];
              local_38 = ppiVar9;
              if ((int **)ppiVar9[1] != ppiVar9) {
                do {
                  ppiVar4 = ppiVar12;
                  if (local_14 == *local_8) break;
                  if ((ppiVar4 < local_10) || (local_10 + 0x2000 <= ppiVar4)) {
                    return 0xfffffff6;
                  }
                  ppiVar8 = (int **)(((uint)ppiVar4 & 0xfffff000) + 0xc);
                  ppiVar12 = (int **)(((uint)ppiVar4 & 0xfffff000) + 0xffc);
                  if (ppiVar8 == ppiVar12) {
                    return 0xfffffff5;
                  }
                  do {
                    if (ppiVar8 == ppiVar4) break;
                    ppiVar8 = (int **)((int)ppiVar8 + ((uint)*ppiVar8 & 0xfffffffe));
                  } while (ppiVar8 != ppiVar12);
                  if (ppiVar8 == ppiVar12) {
                    return 0xfffffff5;
                  }
                  iVar6 = ((int)*ppiVar4 >> 4) + -1;
                  if (0x3f < iVar6) {
                    iVar6 = 0x3f;
                  }
                  if (iVar6 != local_c) {
                    return 0xfffffff4;
                  }
                  if ((int **)ppiVar4[2] != local_38) {
                    return 0xfffffff3;
                  }
                  local_14 = local_14 + 1;
                  ppiVar12 = (int **)ppiVar4[1];
                  local_38 = ppiVar4;
                } while ((int **)ppiVar4[1] != ppiVar9);
                if (local_14 != 0) {
                  if (local_c < 0x20) {
                    uVar5 = 0x80000000 >> ((byte)local_c & 0x1f);
                    local_28 = local_28 | uVar5;
                    local_30 = local_30 | uVar5;
                  }
                  else {
                    uVar5 = 0x80000000 >> ((byte)local_c - 0x20 & 0x1f);
                    local_20 = local_20 | uVar5;
                    local_1c = local_1c | uVar5;
                  }
                }
              }
              if (((int **)local_38[1] != ppiVar9) || (local_14 != *local_8)) {
                return 0xfffffff2;
              }
              if ((int **)ppiVar9[2] != local_38) {
                return 0xfffffff1;
              }
              local_c = local_c + 1;
              local_8 = local_8 + 1;
              puVar10 = local_3c;
              puVar11 = local_40;
              ppiVar9 = ppiVar9 + 2;
            } while (local_c < 0x40);
          }
          if ((local_28 != puVar11[-0x20]) || (local_20 != *puVar11)) {
            return 0xfffffff0;
          }
          local_10 = local_10 + 0x2000;
          local_2c = local_2c + 0x81;
          local_18 = local_18 << 1;
          local_34 = local_34 + 1;
          puVar11 = puVar11 + 1;
        } while (local_34 < 0x20);
        if ((local_30 != *puVar10) || (local_1c != puVar10[1])) {
          return 0xffffffef;
        }
        puVar10 = puVar10 + 5;
        local_24 = local_24 + 1;
        local_40 = puVar11;
      } while (local_24 < DAT_01417010);
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



undefined ** FUN_01404319(void)

{
  bool bVar1;
  int *lpAddress;
  LPVOID pvVar2;
  undefined **ppuVar3;
  int iVar4;
  undefined **lpMem;
  
  if (DAT_014116d0 == -1) {
    lpMem = &PTR_LOOP_014116c0;
  }
  else {
    lpMem = (undefined **)HeapAlloc(DAT_01415fc4,0,0x2020);
    if (lpMem == (undefined **)0x0) {
      return (undefined **)0x0;
    }
  }
  lpAddress = (int *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (int *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if (lpMem == &PTR_LOOP_014116c0) {
        if (PTR_LOOP_014116c0 == (undefined *)0x0) {
          PTR_LOOP_014116c0 = (undefined *)&PTR_LOOP_014116c0;
        }
        if (PTR_LOOP_014116c4 == (undefined *)0x0) {
          PTR_LOOP_014116c4 = (undefined *)&PTR_LOOP_014116c0;
        }
      }
      else {
        *lpMem = (undefined *)&PTR_LOOP_014116c0;
        lpMem[1] = PTR_LOOP_014116c4;
        PTR_LOOP_014116c4 = (undefined *)lpMem;
        *(undefined ***)lpMem[1] = lpMem;
      }
      lpMem[5] = (undefined *)(lpAddress + 0x100000);
      ppuVar3 = lpMem + 6;
      lpMem[3] = (undefined *)(lpMem + 0x26);
      lpMem[4] = (undefined *)lpAddress;
      lpMem[2] = (undefined *)ppuVar3;
      iVar4 = 0;
      do {
        bVar1 = 0xf < iVar4;
        iVar4 = iVar4 + 1;
        *ppuVar3 = (undefined *)((bVar1 - 1 & 0xf1) - 1);
        ppuVar3[1] = (undefined *)0xf1;
        ppuVar3 = ppuVar3 + 2;
      } while (iVar4 < 0x400);
      Initialize_Memory(lpAddress,0,0x10000);
      for (; lpAddress < lpMem[4] + 0x10000; lpAddress = lpAddress + 0x400) {
        *(undefined *)(lpAddress + 0x3e) = 0xff;
        *lpAddress = (int)(lpAddress + 2);
        lpAddress[1] = 0xf0;
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if (lpMem != &PTR_LOOP_014116c0) {
    HeapFree(DAT_01415fc4,0,lpMem);
  }
  return (undefined **)0x0;
}



void __cdecl FUN_0140445d(undefined **param_1)

{
  VirtualFree(param_1[4],0,0x8000);
  if ((undefined **)PTR_LOOP_014136e0 == param_1) {
    PTR_LOOP_014136e0 = param_1[1];
  }
  if (param_1 != &PTR_LOOP_014116c0) {
    *(undefined **)param_1[1] = *param_1;
    *(undefined **)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_01415fc4,0,param_1);
    return;
  }
  DAT_014116d0 = 0xffffffff;
  return;
}



void __cdecl FUN_014044b3(int param_1)

{
  BOOL BVar1;
  undefined **ppuVar2;
  int iVar3;
  undefined **ppuVar4;
  undefined **ppuVar5;
  int local_8;
  
  ppuVar4 = (undefined **)PTR_LOOP_014116c4;
  do {
    ppuVar5 = ppuVar4;
    if (ppuVar4[4] != (undefined *)0xffffffff) {
      local_8 = 0;
      ppuVar5 = ppuVar4 + 0x804;
      iVar3 = 0x3ff000;
      do {
        if (*ppuVar5 == (undefined *)0xf0) {
          BVar1 = VirtualFree(ppuVar4[4] + iVar3,0x1000,0x4000);
          if (BVar1 != 0) {
            *ppuVar5 = (undefined *)0xffffffff;
            DAT_0141590c = DAT_0141590c + -1;
            if (((undefined **)ppuVar4[3] == (undefined **)0x0) || (ppuVar5 < ppuVar4[3])) {
              ppuVar4[3] = (undefined *)ppuVar5;
            }
            local_8 = local_8 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        ppuVar5 = ppuVar5 + -2;
      } while (-1 < iVar3);
      ppuVar5 = (undefined **)ppuVar4[1];
      if ((local_8 != 0) && (ppuVar4[6] == (undefined *)0xffffffff)) {
        ppuVar2 = ppuVar4 + 8;
        iVar3 = 1;
        do {
          if (*ppuVar2 != (undefined *)0xffffffff) break;
          iVar3 = iVar3 + 1;
          ppuVar2 = ppuVar2 + 2;
        } while (iVar3 < 0x400);
        if (iVar3 == 0x400) {
          FUN_0140445d(ppuVar4);
        }
      }
    }
    if ((ppuVar5 == (undefined **)PTR_LOOP_014116c4) || (ppuVar4 = ppuVar5, param_1 < 1)) {
      return;
    }
  } while( true );
}



int __cdecl FUN_01404575(undefined *param_1,int **param_2,uint *param_3)

{
  undefined **ppuVar1;
  uint uVar2;
  
  ppuVar1 = &PTR_LOOP_014116c0;
  while ((param_1 <= ppuVar1[4] || (ppuVar1[5] <= param_1))) {
    ppuVar1 = (undefined **)*ppuVar1;
    if (ppuVar1 == &PTR_LOOP_014116c0) {
      return 0;
    }
  }
  if (((uint)param_1 & 0xf) != 0) {
    return 0;
  }
  if (((uint)param_1 & 0xfff) < 0x100) {
    return 0;
  }
  *param_2 = (int *)ppuVar1;
  uVar2 = (uint)param_1 & 0xfffff000;
  *param_3 = uVar2;
  return ((int)(param_1 + (-0x100 - uVar2)) >> 4) + 8 + uVar2;
}



void __cdecl FUN_014045cc(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  
  piVar1 = (int *)(param_1 + 0x18 + (param_2 - *(int *)(param_1 + 0x10) >> 0xc) * 8);
  *piVar1 = *piVar1 + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_0141590c = DAT_0141590c + 1, DAT_0141590c == 0x20)) {
    FUN_014044b3(0x10);
  }
  return;
}



// WARNING: Type propagation algorithm not settling

int * __cdecl Memory_manager(int *param_1)

{
  int **ppiVar1;
  undefined **ppuVar2;
  undefined *puVar3;
  int **ppiVar4;
  int *piVar5;
  undefined **ppuVar6;
  int *piVar7;
  int **ppiVar8;
  undefined **ppuVar9;
  int local_8;
  
  piVar7 = (int *)PTR_LOOP_014136e0;
  do {
    if (piVar7[4] != -1) {
      ppiVar8 = (int **)piVar7[2];
      ppiVar4 = (int **)(((int)ppiVar8 + (-0x18 - (int)piVar7) >> 3) * 0x1000 + piVar7[4]);
      if (ppiVar8 < piVar7 + 0x806) {
        do {
          if (((int)param_1 <= (int)*ppiVar8) && (param_1 < ppiVar8[1])) {
            piVar5 = (int *)FUN_01404819(ppiVar4,*ppiVar8,param_1);
            if (piVar5 != (int *)0x0) goto LAB_014046dc;
            ppiVar8[1] = param_1;
          }
          ppiVar8 = ppiVar8 + 2;
          ppiVar4 = ppiVar4 + 0x400;
        } while (ppiVar8 < piVar7 + 0x806);
      }
      ppiVar1 = (int **)piVar7[2];
      ppiVar4 = (int **)piVar7[4];
      for (ppiVar8 = (int **)(piVar7 + 6); ppiVar8 < ppiVar1; ppiVar8 = ppiVar8 + 2) {
        if (((int)param_1 <= (int)*ppiVar8) && (param_1 < ppiVar8[1])) {
          piVar5 = (int *)FUN_01404819(ppiVar4,*ppiVar8,param_1);
          if (piVar5 != (int *)0x0) {
LAB_014046dc:
            PTR_LOOP_014136e0 = (undefined *)piVar7;
            *ppiVar8 = (int *)((int)*ppiVar8 - (int)param_1);
            piVar7[2] = (int)ppiVar8;
            return piVar5;
          }
          ppiVar8[1] = param_1;
        }
        ppiVar4 = ppiVar4 + 0x400;
      }
    }
    piVar7 = (int *)*piVar7;
    if (piVar7 == (int *)PTR_LOOP_014136e0) {
      ppuVar9 = &PTR_LOOP_014116c0;
      while ((ppuVar9[4] == (undefined *)0xffffffff || (ppuVar9[3] == (undefined *)0x0))) {
        ppuVar9 = (undefined **)*ppuVar9;
        if (ppuVar9 == &PTR_LOOP_014116c0) {
          ppuVar9 = FUN_01404319();
          if (ppuVar9 == (undefined **)0x0) {
            return (int *)0x0;
          }
          piVar7 = (int *)ppuVar9[4];
          *(char *)(piVar7 + 2) = (char)param_1;
          PTR_LOOP_014136e0 = (undefined *)ppuVar9;
          *piVar7 = (int)(piVar7 + 2) + (int)param_1;
          piVar7[1] = 0xf0 - (int)param_1;
          ppuVar9[6] = ppuVar9[6] + -((uint)param_1 & 0xff);
          return piVar7 + 0x40;
        }
      }
      ppuVar2 = (undefined **)ppuVar9[3];
      local_8 = 0;
      piVar7 = (int *)(ppuVar9[4] + ((int)ppuVar2 + (-0x18 - (int)ppuVar9) >> 3) * 0x1000);
      puVar3 = *ppuVar2;
      ppuVar6 = ppuVar2;
      for (; (puVar3 == (undefined *)0xffffffff && (local_8 < 0x10)); local_8 = local_8 + 1) {
        ppuVar6 = ppuVar6 + 2;
        puVar3 = *ppuVar6;
      }
      piVar5 = (int *)VirtualAlloc(piVar7,local_8 << 0xc,0x1000,4);
      if (piVar5 != piVar7) {
        return (int *)0x0;
      }
      Initialize_Memory(piVar7,local_8 << 0xc,0);
      ppuVar6 = ppuVar2;
      if (0 < local_8) {
        piVar5 = piVar7 + 1;
        do {
          *(undefined *)(piVar5 + 0x3d) = 0xff;
          piVar5[-1] = (int)(piVar5 + 1);
          *piVar5 = 0xf0;
          *ppuVar6 = (undefined *)0xf0;
          ppuVar6[1] = (undefined *)0xf1;
          piVar5 = piVar5 + 0x400;
          ppuVar6 = ppuVar6 + 2;
          local_8 = local_8 + -1;
        } while (local_8 != 0);
      }
      for (; (ppuVar6 < ppuVar9 + 0x806 && (*ppuVar6 != (undefined *)0xffffffff));
          ppuVar6 = ppuVar6 + 2) {
      }
      PTR_LOOP_014136e0 = (undefined *)ppuVar9;
      ppuVar9[3] = (undefined *)(-(uint)(ppuVar6 < ppuVar9 + 0x806) & (uint)ppuVar6);
      *(char *)(piVar7 + 2) = (char)param_1;
      ppuVar9[2] = (undefined *)ppuVar2;
      *ppuVar2 = *ppuVar2 + -(int)param_1;
      piVar7[1] = piVar7[1] - (int)param_1;
      *piVar7 = (int)(piVar7 + 2) + (int)param_1;
      return piVar7 + 0x40;
    }
  } while( true );
}



int __cdecl FUN_01404819(int **param_1,int *param_2,int *param_3)

{
  int **ppiVar1;
  int **ppiVar2;
  byte bVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar2 = (int **)*param_1;
  ppiVar1 = param_1 + 0x3e;
  bVar3 = (byte)param_3;
  if (param_1[1] < param_3) {
    ppiVar4 = (int **)((int)param_1[1] + (int)ppiVar2);
    ppiVar6 = ppiVar2;
    if (*(byte *)ppiVar4 != 0) {
      ppiVar6 = ppiVar4;
    }
    while( true ) {
      while( true ) {
        if (ppiVar1 <= (int **)((int)ppiVar6 + (int)param_3)) {
          ppiVar6 = param_1 + 2;
          while( true ) {
            while( true ) {
              if (ppiVar2 <= ppiVar6) {
                return 0;
              }
              if (ppiVar1 <= (int **)((int)ppiVar6 + (int)param_3)) {
                return 0;
              }
              if (*(byte *)ppiVar6 == 0) break;
              ppiVar6 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
            }
            piVar5 = (int *)0x1;
            ppiVar4 = ppiVar6;
            while (ppiVar4 = (int **)((int)ppiVar4 + 1), *(byte *)ppiVar4 == 0) {
              piVar5 = (int *)((int)piVar5 + 1);
            }
            if (param_3 <= piVar5) break;
            param_2 = (int *)((int)param_2 - (int)piVar5);
            ppiVar6 = ppiVar4;
            if (param_2 < param_3) {
              return 0;
            }
          }
          if ((int **)((int)ppiVar6 + (int)param_3) < ppiVar1) {
            *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
            param_1[1] = (int *)((int)piVar5 - (int)param_3);
          }
          else {
            param_1[1] = (int *)0x0;
            *param_1 = (int *)(param_1 + 2);
          }
          *(byte *)ppiVar6 = bVar3;
          ppiVar2 = ppiVar6 + 2;
          goto LAB_0140492c;
        }
        if (*(byte *)ppiVar6 == 0) break;
        ppiVar6 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      piVar5 = (int *)0x1;
      ppiVar4 = ppiVar6;
      while (ppiVar4 = (int **)((int)ppiVar4 + 1), *(byte *)ppiVar4 == 0) {
        piVar5 = (int *)((int)piVar5 + 1);
      }
      if (param_3 <= piVar5) break;
      if (ppiVar6 == ppiVar2) {
        param_1[1] = piVar5;
        ppiVar6 = ppiVar4;
      }
      else {
        param_2 = (int *)((int)param_2 - (int)piVar5);
        ppiVar6 = ppiVar4;
        if (param_2 < param_3) {
          return 0;
        }
      }
    }
    if ((int **)((int)ppiVar6 + (int)param_3) < ppiVar1) {
      *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
      param_1[1] = (int *)((int)piVar5 - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    *(byte *)ppiVar6 = bVar3;
    ppiVar2 = ppiVar6 + 2;
  }
  else {
    *(byte *)ppiVar2 = bVar3;
    if ((int **)((int)ppiVar2 + (int)param_3) < ppiVar1) {
      *param_1 = (int *)((int)*param_1 + (int)param_3);
      param_1[1] = (int *)((int)param_1[1] - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    ppiVar2 = ppiVar2 + 2;
  }
LAB_0140492c:
  return (int)ppiVar2 * 0x10 + (int)param_1 * -0xf;
}



undefined4 __cdecl FUN_0140493d(int param_1,int **param_2,int **param_3,uint param_4)

{
  int **ppiVar1;
  int *piVar2;
  char cVar3;
  int **ppiVar4;
  int *piVar5;
  uint uVar6;
  
  uVar6 = (uint)*(byte *)param_3;
  piVar2 = (int *)(param_1 + 0x18 + ((int)param_2 - *(int *)(param_1 + 0x10) >> 0xc) * 8);
  if (param_4 < uVar6) {
    *(undefined *)param_3 = (undefined)param_4;
    *piVar2 = *piVar2 + (uVar6 - param_4);
    piVar2[1] = 0xf1;
  }
  else {
    if (param_4 <= uVar6) {
      return 0;
    }
    ppiVar1 = (int **)((int)param_3 + param_4);
    if (param_2 + 0x3e < ppiVar1) {
      return 0;
    }
    for (ppiVar4 = (int **)(uVar6 + (int)param_3); (ppiVar4 < ppiVar1 && (*(char *)ppiVar4 == '\0'))
        ; ppiVar4 = (int **)((int)ppiVar4 + 1)) {
    }
    if (ppiVar4 != ppiVar1) {
      return 0;
    }
    *(undefined *)param_3 = (undefined)param_4;
    if ((param_3 <= *param_2) && (*param_2 < ppiVar1)) {
      if (ppiVar1 < param_2 + 0x3e) {
        piVar5 = (int *)0x0;
        *param_2 = (int *)ppiVar1;
        cVar3 = *(char *)ppiVar1;
        while (cVar3 == '\0') {
          piVar5 = (int *)((int)piVar5 + 1);
          cVar3 = *(char *)((int)ppiVar1 + (int)piVar5);
        }
        param_2[1] = piVar5;
      }
      else {
        param_2[1] = (int *)0x0;
        *param_2 = (int *)(param_2 + 2);
      }
    }
    *piVar2 = *piVar2 + (uVar6 - param_4);
  }
  return 1;
}



int FUN_014049e6(void)

{
  int *piVar1;
  byte bVar2;
  undefined **ppuVar3;
  int iVar4;
  int iVar5;
  int **ppiVar6;
  int **ppiVar7;
  undefined **local_24;
  int local_20;
  int local_1c;
  undefined *local_14;
  int local_10;
  int local_c;
  int local_8;
  
  local_20 = 0;
  local_24 = &PTR_LOOP_014116c0;
  do {
    if ((undefined **)PTR_LOOP_014136e0 == local_24) {
      local_20 = local_20 + 1;
    }
    ppiVar6 = (int **)local_24[4];
    if (ppiVar6 != (int **)0xffffffff) {
      local_1c = 0;
      local_10 = 0;
      ppuVar3 = local_24 + 6;
      ppiVar7 = ppiVar6 + 2;
      do {
        if (*ppuVar3 == (undefined *)0xffffffff) {
          if ((local_10 == 0) && ((undefined **)local_24[3] != ppuVar3)) {
            return -1;
          }
          local_10 = local_10 + 1;
        }
        else {
          if (ppiVar7 + 0x3c <= *ppiVar6) {
            return -2;
          }
          if (*(char *)(ppiVar7 + 0x3c) != -1) {
            return -3;
          }
          local_c = 0;
          local_14 = (undefined *)0x0;
          local_8 = 0;
          iVar4 = 0;
          do {
            piVar1 = (int *)((int)ppiVar7 + iVar4);
            if (piVar1 == *ppiVar6) {
              local_c = local_c + 1;
            }
            if (*(byte *)piVar1 == 0) {
              local_14 = local_14 + 1;
              local_8 = local_8 + 1;
              iVar5 = iVar4 + 1;
            }
            else {
              if ((int)ppuVar3[1] <= local_8) {
                return -4;
              }
              if (local_c == 1) {
                if (local_8 < (int)ppiVar7[-1]) {
                  return -5;
                }
                local_c = 2;
              }
              local_8 = 0;
              bVar2 = *(byte *)piVar1;
              iVar5 = iVar4;
              while (iVar5 = iVar5 + 1, iVar5 < (int)((uint)bVar2 + iVar4)) {
                if (*(char *)((int)ppiVar7 + iVar5) != '\0') {
                  return -6;
                }
                bVar2 = *(byte *)(iVar4 + 8 + (int)ppiVar6);
              }
            }
            iVar4 = iVar5;
          } while (iVar5 < 0xf0);
          if (local_14 != *ppuVar3) {
            return -7;
          }
          if (local_c == 0) {
            return -8;
          }
        }
        local_1c = local_1c + 1;
        ppuVar3 = ppuVar3 + 2;
        ppiVar6 = ppiVar6 + 0x400;
        ppiVar7 = ppiVar7 + 0x400;
      } while (local_1c < 0x400);
    }
    local_24 = (undefined **)*local_24;
    if (local_24 == &PTR_LOOP_014116c0) {
      return (-(uint)(local_20 != 0) & 9) - 9;
    }
  } while( true );
}



// Library Function - Single Match
//  _strncpy
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  
  if (_Count == 0) {
    return _Dest;
  }
  puVar5 = (uint *)_Dest;
  if (((uint)_Source & 3) != 0) {
    while( true ) {
      cVar3 = *_Source;
      _Source = (char *)((int)_Source + 1);
      *(char *)puVar5 = cVar3;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
      if (_Count == 0) {
        return _Dest;
      }
      if (cVar3 == '\0') break;
      if (((uint)_Source & 3) == 0) {
        uVar4 = _Count >> 2;
        goto joined_r0x01404b8e;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_01404bcb;
        goto LAB_01404c39;
      }
      *(undefined *)puVar5 = 0;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
    } while (_Count != 0);
    return _Dest;
  }
  uVar4 = _Count >> 2;
  if (uVar4 != 0) {
    do {
      uVar1 = *(uint *)_Source;
      uVar2 = *(uint *)_Source;
      _Source = (char *)((int)_Source + 4);
      if (((uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar2 == '\0') {
          *puVar5 = 0;
joined_r0x01404c35:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_01404c39:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_01404bcb;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x01404c35;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x01404c35;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x01404c35;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x01404b8e:
    } while (uVar4 != 0);
    _Count = _Count & 3;
    if (_Count == 0) {
      return _Dest;
    }
  }
  do {
    cVar3 = *_Source;
    _Source = (char *)((int)_Source + 1);
    *(char *)puVar5 = cVar3;
    puVar5 = (uint *)((int)puVar5 + 1);
    if (cVar3 == '\0') {
      while (_Count = _Count - 1, _Count != 0) {
LAB_01404bcb:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



void __cdecl FUN_01404c4e(undefined *param_1)

{
  uint *puVar1;
  undefined4 *unaff_FS_OFFSET;
  int *local_2c;
  uint *local_28;
  uint local_24;
  uint *local_20;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f218;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (param_1 == (undefined *)0x0) goto LAB_01404d28;
  if (DAT_01415fc8 == 3) {
    critical_code_area_executor(9);
    local_8 = 0;
    local_20 = (uint *)FUN_014033f8((int)param_1);
    if (local_20 != (uint *)0x0) {
      FUN_01403423(local_20,(int)param_1);
    }
    local_8 = 0xffffffff;
    FUN_01404cb8();
    puVar1 = local_20;
LAB_01404d09:
    if (puVar1 != (uint *)0x0) goto LAB_01404d28;
  }
  else if (DAT_01415fc8 == 2) {
    critical_code_area_executor(9);
    local_8 = 1;
    local_28 = (uint *)FUN_01404575(param_1,&local_2c,&local_24);
    if (local_28 != (uint *)0x0) {
      FUN_014045cc((int)local_2c,local_24,(byte *)local_28);
    }
    local_8 = 0xffffffff;
    FUN_01404d10();
    puVar1 = local_28;
    goto LAB_01404d09;
  }
  HeapFree(DAT_01415fc4,0,param_1);
LAB_01404d28:
  *unaff_FS_OFFSET = local_14;
  return;
}



void FUN_01404cb8(void)

{
  endCriticalFromID(9);
  return;
}



void FUN_01404d10(void)

{
  endCriticalFromID(9);
  return;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2003 Release

void * __cdecl _malloc(size_t mem_Size)

{
  void *Memory;
  
  Memory = malloc_mem(mem_Size,DAT_014159cc);
  return Memory;
}



// Library Function - Single Match
//  __nh_malloc
// 
// Library: Visual Studio 2003 Release

void * __cdecl malloc_mem(size_t mem_Size,int error_Flag)

{
  void *mem_return;
  int mem_rite;
  
  if (mem_Size < 0xffffffe1) {
    do {
      mem_return = (void *)Speicherallokation((uint *)mem_Size);
      if (mem_return != (void *)0x0) {
        return mem_return;
      }
      if (error_Flag == 0) {
        return (void *)0x0;
      }
      mem_rite = CheckMemoryAllocation(mem_Size);
    } while (mem_rite != 0);
  }
  return (void *)0x0;
}



// WTF Why?
//   undefined4 *unaff_FS_OFFSET;
//   undefined4 local_14;

void __cdecl Speicherallokation(uint *mem_size)

{
  int *piVar1;
  uint dwBytes;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f230;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_01415fc8 == 3) {
    if (mem_size <= DAT_01417018) {
      critical_code_area_executor(9);
      local_8 = 0;
      piVar1 = Allocate_Memory(mem_size);
      local_8 = 0xffffffff;
      endCritical_9();
      if (piVar1 != (int *)0x0) goto LAB_01404e62;
    }
LAB_01404e44:
    if (mem_size == (uint *)0x0) {
      mem_size = (uint *)0x1;
    }
    dwBytes = (int)mem_size + 0xfU & 0xfffffff0;
  }
  else {
    if (DAT_01415fc8 != 2) goto LAB_01404e44;
    if (mem_size == (uint *)0x0) {
      dwBytes = 0x10;
    }
    else {
      dwBytes = (int)mem_size + 0xfU & 0xfffffff0;
    }
    if (dwBytes <= DAT_014136e4) {
      critical_code_area_executor(9);
      local_8 = 1;
      piVar1 = Memory_manager((int *)(dwBytes >> 4));
      local_8 = 0xffffffff;
      endCritical_9();
      if (piVar1 != (int *)0x0) goto LAB_01404e62;
    }
  }
  HeapAlloc(DAT_01415fc4,0,dwBytes);
LAB_01404e62:
  *unaff_FS_OFFSET = local_14;
  return;
}



void endCritical_9(void)

{
  endCriticalFromID(9);
  return;
}



void endCritical_9(void)

{
  endCriticalFromID(9);
  return;
}



uint __cdecl FUN_01404e71(byte param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  uint uVar3;
  uint uVar4;
  void *this;
  undefined *puVar5;
  undefined *this_00;
  
  pbVar2 = param_2;
  if (param_2[1] == 0x3a) {
    pbVar2 = param_2 + 2;
  }
  bVar1 = *pbVar2;
  if ((((bVar1 == 0x5c) || (bVar1 == 0x2f)) && (pbVar2[1] == 0)) ||
     (((param_1 & 0x10) != 0 || (uVar4 = 0x8000, bVar1 == 0)))) {
    uVar4 = 0x4040;
  }
  this = (void *)0x2e;
  uVar4 = uVar4 | (uint)(~param_1 & 1 | 2) << 7;
  pbVar2 = FUN_014076a2(param_2,0x2e);
  if (pbVar2 != (byte *)0x0) {
    puVar5 = &DAT_0140f260;
    uVar3 = FUN_0140750d(this,pbVar2,&DAT_0140f260);
    if (uVar3 != 0) {
      this_00 = &DAT_0140f258;
      uVar3 = FUN_0140750d(puVar5,pbVar2,&DAT_0140f258);
      if (uVar3 != 0) {
        puVar5 = &DAT_0140f250;
        uVar3 = FUN_0140750d(this_00,pbVar2,&DAT_0140f250);
        if (uVar3 != 0) {
          uVar3 = FUN_0140750d(puVar5,pbVar2,&DAT_0140f248);
          if (uVar3 != 0) goto LAB_01404f12;
        }
      }
    }
    uVar4 = uVar4 | 0x40;
  }
LAB_01404f12:
  return (uVar4 & 0x1c0) >> 6 | uVar4 | uVar4 >> 3 & 0x38;
}



undefined4 __cdecl FUN_01404f29(byte *param_1,int *param_2)

{
  byte *pbVar1;
  DWORD *pDVar2;
  uint uVar3;
  uint *_Str;
  size_t sVar4;
  int iVar5;
  UINT UVar6;
  BOOL BVar7;
  DWORD DVar8;
  uint local_268 [65];
  _WIN32_FIND_DATAA local_164;
  int local_24;
  _FILETIME local_20;
  HANDLE local_18;
  _SYSTEMTIME local_14;
  
  pbVar1 = FUN_014078ea(param_1,&DAT_0140f26c);
  if (pbVar1 != (byte *)0x0) {
LAB_01404f5c:
    pDVar2 = FUN_01406c66();
    *pDVar2 = 2;
    pDVar2 = FUN_01406c6f();
    *pDVar2 = 2;
    return 0xffffffff;
  }
  if (param_1[1] == 0x3a) {
    if ((*param_1 != 0) && (param_1[2] == 0)) goto LAB_01404f5c;
    uVar3 = FUN_0140786f((int)(char)*param_1);
    local_24 = uVar3 - 0x60;
  }
  else {
    local_24 = FUN_014077b9();
  }
  local_18 = FindFirstFileA((LPCSTR)param_1,&local_164);
  if (local_18 == (HANDLE)0xffffffff) {
    pbVar1 = FUN_014078ea(param_1,&DAT_0140f268);
    if ((((pbVar1 == (byte *)0x0) ||
         (_Str = FUN_01407714(local_268,(LPCSTR)param_1,0x104), _Str == (uint *)0x0)) ||
        ((sVar4 = _strlen((char *)_Str), sVar4 != 3 &&
         (iVar5 = FUN_014051e4((char *)_Str), iVar5 == 0)))) ||
       (UVar6 = GetDriveTypeA((LPCSTR)_Str), UVar6 < 2)) {
      pDVar2 = FUN_01406c66();
      *pDVar2 = 2;
      pDVar2 = FUN_01406c6f();
      *pDVar2 = 2;
      return 0xffffffff;
    }
    local_164.dwFileAttributes = 0x10;
    local_164.nFileSizeHigh = 0;
    local_164.nFileSizeLow = 0;
    local_164.cFileName[0] = '\0';
    iVar5 = ConvertSystemTimeToTimeT(0x7bc,1,1,0,0,0,-1);
    param_2[7] = iVar5;
    param_2[6] = iVar5;
    param_2[8] = iVar5;
  }
  else {
    BVar7 = FileTimeToLocalFileTime(&local_164.ftLastWriteTime,&local_20);
    if ((BVar7 == 0) || (BVar7 = FileTimeToSystemTime(&local_20,&local_14), BVar7 == 0)) {
LAB_014051c7:
      DVar8 = GetLastError();
      FUN_01406bf3(DVar8);
      FindClose(local_18);
      return 0xffffffff;
    }
    iVar5 = ConvertSystemTimeToTimeT
                      ((uint)local_14.wYear,(uint)local_14.wMonth,(uint)local_14.wDay,
                       (uint)local_14.wHour,(uint)local_14.wMinute,(uint)local_14.wSecond,-1);
    param_2[7] = iVar5;
    if ((local_164.ftLastAccessTime.dwLowDateTime != 0) ||
       (local_164.ftLastAccessTime.dwHighDateTime != 0)) {
      BVar7 = FileTimeToLocalFileTime(&local_164.ftLastAccessTime,&local_20);
      if ((BVar7 == 0) || (BVar7 = FileTimeToSystemTime(&local_20,&local_14), BVar7 == 0))
      goto LAB_014051c7;
      iVar5 = ConvertSystemTimeToTimeT
                        ((uint)local_14.wYear,(uint)local_14.wMonth,(uint)local_14.wDay,
                         (uint)local_14.wHour,(uint)local_14.wMinute,(uint)local_14.wSecond,-1);
    }
    param_2[6] = iVar5;
    if ((local_164.ftCreationTime.dwLowDateTime == 0) &&
       (local_164.ftCreationTime.dwHighDateTime == 0)) {
      iVar5 = param_2[7];
    }
    else {
      BVar7 = FileTimeToLocalFileTime(&local_164.ftCreationTime,&local_20);
      if ((BVar7 == 0) || (BVar7 = FileTimeToSystemTime(&local_20,&local_14), BVar7 == 0))
      goto LAB_014051c7;
      iVar5 = ConvertSystemTimeToTimeT
                        ((uint)local_14.wYear,(uint)local_14.wMonth,(uint)local_14.wDay,
                         (uint)local_14.wHour,(uint)local_14.wMinute,(uint)local_14.wSecond,-1);
    }
    param_2[8] = iVar5;
    FindClose(local_18);
  }
  uVar3 = FUN_01404e71((byte)local_164.dwFileAttributes,param_1);
  *(short *)((int)param_2 + 6) = (short)uVar3;
  param_2[5] = local_164.nFileSizeLow;
  *param_2 = local_24 + -1;
  param_2[4] = local_24 + -1;
  *(undefined2 *)(param_2 + 2) = 1;
  *(undefined2 *)(param_2 + 1) = 0;
  *(undefined2 *)(param_2 + 3) = 0;
  *(undefined2 *)((int)param_2 + 10) = 0;
  return 0;
}



undefined4 __cdecl FUN_014051e4(char *param_1)

{
  char *pcVar1;
  size_t sVar2;
  char *pcVar3;
  char cVar4;
  
  sVar2 = _strlen(param_1);
  if (((4 < sVar2) && ((*param_1 == '\\' || (*param_1 == '/')))) &&
     ((param_1[1] == '\\' || (param_1[1] == '/')))) {
    pcVar3 = param_1 + 3;
    cVar4 = param_1[3];
    while (((cVar4 != '\0' && (cVar4 != '\\')) && (cVar4 != '/'))) {
      pcVar1 = pcVar3 + 1;
      pcVar3 = pcVar3 + 1;
      cVar4 = *pcVar1;
    }
    if ((*pcVar3 != '\0') && (pcVar3 = pcVar3 + 1, *pcVar3 != '\0')) {
      for (; (cVar4 = *pcVar3, cVar4 != '\0' && ((cVar4 != '\\' && (cVar4 != '/'))));
          pcVar3 = pcVar3 + 1) {
      }
      if ((*pcVar3 == '\0') || (pcVar3[1] == '\0')) {
        return 1;
      }
    }
  }
  return 0;
}



void __cdecl FUN_01405254(int param_1,uint *param_2,uint **param_3)

{
  FUN_0140797f(param_1,param_2,param_3,(uint **)0x0);
  return;
}



undefined4 __cdecl FUN_0140526b(LPCSTR param_1)

{
  undefined uVar1;
  BOOL BVar2;
  DWORD DVar3;
  uint uVar4;
  byte local_10c;
  byte local_10b;
  
  BVar2 = SetCurrentDirectoryA(param_1);
  if (BVar2 != 0) {
    DVar3 = GetCurrentDirectoryA(0x105,(LPSTR)&local_10c);
    if (DVar3 != 0) {
      if (((local_10c != 0x5c) && (local_10c != 0x2f)) || (local_10c != local_10b)) {
        param_1 = (LPCSTR)CONCAT31(param_1._1_3_,0x3d);
        uVar4 = FUN_01407b19((uint)local_10c);
        uVar1 = SUB41(param_1,0);
        param_1 = (LPCSTR)(uint)CONCAT12(0x3a,CONCAT11((char)uVar4,uVar1));
        BVar2 = SetEnvironmentVariableA((LPCSTR)&param_1,(LPCSTR)&local_10c);
        if (BVar2 == 0) goto LAB_014052df;
      }
      return 0;
    }
  }
LAB_014052df:
  DVar3 = GetLastError();
  FUN_01406bf3(DVar3);
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  DWORD Version;
  int iVar1;
  HKEY pHVar2;
  HMODULE Win_Modul;
  UINT exit_code;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uVar3;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  _EXCEPTION_POINTERS *local_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f270;
  puStack_10 = &LAB_014073f0;
  uStack_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_14;
  local_1c = &stack0xffffff88;
  Version = GetVersion();
  _DAT_0141592c = Version >> 8 & 0xff;
  _DAT_01415928 = Version & 0xff;
  _DAT_01415924 = _DAT_01415928 * 0x100 + _DAT_0141592c;
  _DAT_01415920 = Version >> 0x10;
  iVar1 = FUN_01406eaf(1);
  if (iVar1 == 0) {
    FUN_0140541e(0x1c);
  }
  iVar1 = TLS_Thread_Local_Storage();
  if (iVar1 == 0) {
    FUN_0140541e(0x10);
  }
  local_8 = 0;
  FUN_0140819c();
  DAT_01416ff8 = GetCommandLineA();
  DAT_01415910 = FUN_0140806a();
  FUN_01407e1d();
  FUN_01407d64();
  FUN_01405442();
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  pHVar2 = (HKEY)FUN_01407d0c();
  uVar3 = 0;
  Win_Modul = GetModuleHandleA((LPCSTR)0x0);
  exit_code = FUN_01401746(Win_Modul,uVar3,pHVar2);
  __exit2(exit_code);
  FUN_01407b94(local_18->ExceptionRecord->ExceptionCode,local_18);
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2003 Release

void __cdecl __amsg_exit(int exitCode)

{
  if (exitFlag == 1) {
    performExitRoutine();
  }
  executeExitProcedure(exitCode);
  (*(code *)PTR___exit1_014136f0)(0xff);
  return;
}



void __cdecl FUN_0140541e(DWORD input)

{
  if (exitFlag == 1) {
    performExitRoutine();
  }
  executeExitProcedure(input);
                    // WARNING: Subroutine does not return
  ExitProcess(0xff);
}



void FUN_01405442(void)

{
  if (DAT_01416ff4 != (code *)0x0) {
    (*DAT_01416ff4)();
  }
  callValidFunctionPointers((undefined **)&DAT_01411010,(undefined **)&DAT_01411020);
  callValidFunctionPointers((undefined **)&DAT_01411000,(undefined **)&DAT_0141100c);
  return;
}



// WTF I don't know why? But Ok

void __cdecl __exit2(UINT exit_code)

{
  exit_handeler(exit_code,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2003 Release
// 
// skips diss:
// 
//   if (param_2 == 0) {
//     if ((DAT_01416ff0 != (code **)0x0) &&
//        (functionPointerPtr = (code **)(DAT_01416fec - 4), DAT_01416ff0 <= functionPointerPtr)) {
//       do {
//         if (*functionPointerPtr != (code *)0x0) {
//           (**functionPointerPtr)();
//         }
//         functionPointerPtr = functionPointerPtr + -1;
//       } while (DAT_01416ff0 <= functionPointerPtr);
//     }

void __cdecl __exit1(int exit_Code)

{
  exit_handeler(exit_Code,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Don't ask me what exit dos :D

void __cdecl exit_handeler(UINT input_exitcode,int Skipe,int exit)

{
  HANDLE Aktive_Process;
  code **functionPointerPtr;
  UINT ExitCode;
  
  execude_0xd();
  if (mem_exit == 1) {
    ExitCode = input_exitcode;
    Aktive_Process = GetCurrentProcess();
    TerminateProcess(Aktive_Process,ExitCode);
  }
  _is_terminatet = 1;
  DAT_01415954 = (undefined)exit;
  if (Skipe == 0) {
    if ((DAT_01416ff0 != (code **)0x0) &&
       (functionPointerPtr = (code **)(DAT_01416fec - 4), DAT_01416ff0 <= functionPointerPtr)) {
      do {
        if (*functionPointerPtr != (code *)0x0) {
          (**functionPointerPtr)();
        }
        functionPointerPtr = functionPointerPtr + -1;
      } while (DAT_01416ff0 <= functionPointerPtr);
    }
    callValidFunctionPointers((undefined **)&DAT_01411024,(undefined **)&DAT_0141102c);
  }
  callValidFunctionPointers((undefined **)&DAT_01411030,(undefined **)&DAT_01411034);
  if (exit == 0) {
    mem_exit = 1;
                    // WARNING: Subroutine does not return
    ExitProcess(input_exitcode);
  }
  endCritical_0xd();
  return;
}



void execude_0xd(void)

{
  critical_code_area_executor(0xd);
  return;
}



void endCritical_0xd(void)

{
  endCriticalFromID(0xd);
  return;
}



void __cdecl callValidFunctionPointers(undefined **param_1,undefined **param_2)

{
  for (; param_1 < param_2; param_1 = (code **)param_1 + 1) {
    if ((code *)*param_1 != (code *)0x0) {
      (*(code *)*param_1)();
    }
  }
  return;
}



int ** __cdecl FUN_01405580(int **param_1,uint *param_2)

{
  int iVar1;
  uint *puVar2;
  int **ppiVar3;
  undefined4 *unaff_FS_OFFSET;
  int *local_3c;
  uint *local_38;
  int **local_34;
  int **local_30;
  uint *local_2c;
  int **local_28;
  uint *local_24;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f280;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  ppiVar3 = (int **)0x0;
  if (param_1 == (int **)0x0) {
    local_28 = (int **)_malloc((size_t)param_2);
  }
  else {
    if (param_2 == (uint *)0x0) {
      FUN_01404c4e((undefined *)param_1);
    }
    else if (DAT_01415fc8 == 3) {
      do {
        local_28 = (int **)0x0;
        if (param_2 < (uint *)0xffffffe1) {
          critical_code_area_executor(9);
          local_8 = 0;
          local_2c = (uint *)FUN_014033f8((int)param_1);
          if (local_2c != (uint *)0x0) {
            if (param_2 <= DAT_01417018) {
              iVar1 = FUN_01403c01(local_2c,(int)param_1,(int)param_2);
              if (iVar1 == 0) {
                local_28 = (int **)Allocate_Memory(param_2);
                if (local_28 != (int **)0x0) {
                  local_24 = (uint *)((int)param_1[-1] - 1);
                  puVar2 = local_24;
                  if (param_2 <= local_24) {
                    puVar2 = param_2;
                  }
                  FUN_01402ad0(local_28,param_1,(uint)puVar2);
                  local_2c = (uint *)FUN_014033f8((int)param_1);
                  FUN_01403423(local_2c,(int)param_1);
                }
              }
              else {
                local_28 = param_1;
              }
            }
            if (local_28 == (int **)0x0) {
              if (param_2 == (uint *)0x0) {
                param_2 = (uint *)0x1;
              }
              param_2 = (uint *)((int)param_2 + 0xfU & 0xfffffff0);
              local_28 = (int **)HeapAlloc(DAT_01415fc4,0,(SIZE_T)param_2);
              if (local_28 != (int **)0x0) {
                local_24 = (uint *)((int)param_1[-1] - 1);
                puVar2 = local_24;
                if (param_2 <= local_24) {
                  puVar2 = param_2;
                }
                FUN_01402ad0(local_28,param_1,(uint)puVar2);
                FUN_01403423(local_2c,(int)param_1);
              }
            }
          }
          local_8 = 0xffffffff;
          FUN_0140570b();
          if (local_2c == (uint *)0x0) {
            if (param_2 == (uint *)0x0) {
              param_2 = (uint *)0x1;
            }
            param_2 = (uint *)((int)param_2 + 0xfU & 0xfffffff0);
            local_28 = (int **)HeapReAlloc(DAT_01415fc4,0,param_1,(SIZE_T)param_2);
          }
        }
        if ((local_28 != (int **)0x0) || (DAT_014159cc == (int **)0x0)) goto LAB_014058a0;
        iVar1 = CheckMemoryAllocation((int)param_2);
      } while (iVar1 != 0);
    }
    else if (DAT_01415fc8 == 2) {
      if (param_2 < (uint *)0xffffffe1) {
        if (param_2 == (uint *)0x0) {
          param_2 = (uint *)0x10;
        }
        else {
          param_2 = (uint *)((int)param_2 + 0xfU & 0xfffffff0);
        }
      }
      do {
        local_28 = ppiVar3;
        if (param_2 < (uint *)0xffffffe1) {
          critical_code_area_executor(9);
          local_8 = 1;
          ppiVar3 = (int **)FUN_01404575((undefined *)param_1,&local_3c,(uint *)&local_30);
          local_34 = ppiVar3;
          if (ppiVar3 == (int **)0x0) {
            local_28 = (int **)HeapReAlloc(DAT_01415fc4,0,param_1,(SIZE_T)param_2);
          }
          else {
            if (param_2 < DAT_014136e4) {
              iVar1 = FUN_0140493d((int)local_3c,local_30,ppiVar3,(uint)(int *)((uint)param_2 >> 4))
              ;
              if (iVar1 == 0) {
                local_28 = (int **)Memory_manager((int *)((uint)param_2 >> 4));
                if (local_28 != (int **)0x0) {
                  local_38 = (uint *)((uint)*(byte *)ppiVar3 << 4);
                  puVar2 = local_38;
                  if (param_2 <= local_38) {
                    puVar2 = param_2;
                  }
                  FUN_01402ad0(local_28,param_1,(uint)puVar2);
                  FUN_014045cc((int)local_3c,(int)local_30,(byte *)ppiVar3);
                }
              }
              else {
                local_28 = param_1;
              }
            }
            if ((local_28 == (int **)0x0) &&
               (local_28 = (int **)HeapAlloc(DAT_01415fc4,0,(SIZE_T)param_2),
               local_28 != (int **)0x0)) {
              local_38 = (uint *)((uint)*(byte *)ppiVar3 << 4);
              puVar2 = local_38;
              if (param_2 <= local_38) {
                puVar2 = param_2;
              }
              FUN_01402ad0(local_28,param_1,(uint)puVar2);
              FUN_014045cc((int)local_3c,(int)local_30,(byte *)ppiVar3);
            }
          }
          local_8 = 0xffffffff;
          FUN_01405859();
        }
        if ((local_28 != ppiVar3) || (DAT_014159cc == ppiVar3)) goto LAB_014058a0;
        iVar1 = CheckMemoryAllocation((int)param_2);
      } while (iVar1 != 0);
    }
    else {
      do {
        local_28 = (int **)0x0;
        if (param_2 < (uint *)0xffffffe1) {
          if (param_2 == (uint *)0x0) {
            param_2 = (uint *)0x1;
          }
          param_2 = (uint *)((int)param_2 + 0xfU & 0xfffffff0);
          local_28 = (int **)HeapReAlloc(DAT_01415fc4,0,param_1,(SIZE_T)param_2);
        }
        if ((local_28 != (int **)0x0) || (DAT_014159cc == (int **)0x0)) goto LAB_014058a0;
        iVar1 = CheckMemoryAllocation((int)param_2);
      } while (iVar1 != 0);
    }
    local_28 = (int **)0x0;
  }
LAB_014058a0:
  *unaff_FS_OFFSET = local_14;
  return local_28;
}



void FUN_0140570b(void)

{
  endCriticalFromID(9);
  return;
}



void FUN_01405859(void)

{
  endCriticalFromID(9);
  return;
}



SIZE_T __cdecl FUN_014058af(undefined *param_1)

{
  byte *pbVar1;
  SIZE_T SVar2;
  undefined4 *unaff_FS_OFFSET;
  int *local_30;
  byte *local_2c;
  uint local_28;
  SIZE_T local_24;
  byte *local_20;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f298;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_01415fc8 == 3) {
    critical_code_area_executor(9);
    local_8 = 0;
    local_20 = (byte *)FUN_014033f8((int)param_1);
    if (local_20 != (byte *)0x0) {
      local_24 = *(int *)(param_1 + -4) - 9;
    }
    SVar2 = local_24;
    local_8 = 0xffffffff;
    FUN_01405919();
    pbVar1 = local_20;
LAB_0140596b:
    if (pbVar1 != (byte *)0x0) goto LAB_01405980;
  }
  else if (DAT_01415fc8 == 2) {
    critical_code_area_executor(9);
    local_8 = 1;
    local_2c = (byte *)FUN_01404575(param_1,&local_30,&local_28);
    if (local_2c != (byte *)0x0) {
      local_24 = (uint)*local_2c << 4;
    }
    SVar2 = local_24;
    local_8 = 0xffffffff;
    FUN_01405994();
    pbVar1 = local_2c;
    goto LAB_0140596b;
  }
  SVar2 = HeapSize(DAT_01415fc4,0,param_1);
LAB_01405980:
  *unaff_FS_OFFSET = local_14;
  return SVar2;
}



void FUN_01405919(void)

{
  endCriticalFromID(9);
  return;
}



void FUN_01405994(void)

{
  endCriticalFromID(9);
  return;
}



void Initialize_Thread_Local_Storage(void)

{
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_0141373c);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_0141372c);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_0141371c);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_014136fc);
  return;
}



void __cdecl critical_code_area_executor(int mem_adresse)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION CriticalSection;
  
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_014136f8 + mem_adresse * 4);
  if (*(int *)(&DAT_014136f8 + mem_adresse * 4) == 0) {
    CriticalSection = (LPCRITICAL_SECTION)_malloc(0x18);
    if (CriticalSection == (LPCRITICAL_SECTION)0x0) {
      __amsg_exit(0x11);
    }
    critical_code_area_executor(0x11);
    if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
      InitializeCriticalSection(CriticalSection);
      *pp_Var1 = CriticalSection;
    }
    else {
      FUN_01404c4e((undefined *)CriticalSection);
    }
    endCriticalFromID(0x11);
  }
  EnterCriticalSection(*pp_Var1);
  return;
}



void __cdecl endCriticalFromID(int param_1)

{
  LeaveCriticalSection(*(LPCRITICAL_SECTION *)(&DAT_014136f8 + param_1 * 4));
  return;
}



uint __thiscall FUN_01405ac0(void *this,int param_1,uint param_2)

{
  BOOL BVar1;
  int iVar2;
  uint local_8;
  
  if (param_1 + 1U < 0x101) {
    param_1._2_2_ = *(ushort *)(PTR_DAT_014137b8 + param_1 * 2);
  }
  else {
    if ((PTR_DAT_014137b8[(param_1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      local_8 = CONCAT31((int3)((uint)this >> 8),(char)param_1) & 0xffff00ff;
      iVar2 = 1;
    }
    else {
      local_8._0_2_ = CONCAT11((char)param_1,(char)((uint)param_1 >> 8));
      local_8 = CONCAT22((short)((uint)this >> 0x10),(undefined2)local_8) & 0xff00ffff;
      iVar2 = 2;
    }
    BVar1 = FUN_01408701(1,(LPCSTR)&local_8,iVar2,(LPWORD)((int)&param_1 + 2),0,0,1);
    if (BVar1 == 0) {
      return 0;
    }
  }
  return param_1._2_2_ & param_2;
}



void __cdecl FUN_01405bf1(uint param_1)

{
  if ((0x14139cf < param_1) && (param_1 < 0x1413c31)) {
    critical_code_area_executor(((int)(param_1 + 0xfebec630) >> 5) + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_01405c20(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    critical_code_area_executor(param_1 + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



void __cdecl FUN_01405c43(uint param_1)

{
  if ((0x14139cf < param_1) && (param_1 < 0x1413c31)) {
    endCriticalFromID(((int)(param_1 + 0xfebec630) >> 5) + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_01405c72(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    endCriticalFromID(param_1 + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



undefined4 __cdecl FUN_01405c95(uint param_1)

{
  undefined4 uVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01408d0f(param_1);
    uVar1 = FUN_01405cf2(param_1);
    FUN_01408d6e(param_1);
    return uVar1;
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  pDVar2 = FUN_01406c6f();
  *pDVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_01405cf2(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 uVar5;
  
  iVar1 = FUN_01408c26(param_1);
  if (iVar1 != -1) {
    if ((param_1 == 1) || (param_1 == 2)) {
      iVar1 = FUN_01408c26(2);
      iVar2 = FUN_01408c26(1);
      if (iVar2 == iVar1) goto LAB_01405d40;
    }
    hObject = (HANDLE)FUN_01408c26(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_01405d42;
    }
  }
LAB_01405d40:
  DVar4 = 0;
LAB_01405d42:
  FUN_01408ba7(param_1);
  *(undefined *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) = 0;
  if (DVar4 == 0) {
    uVar5 = 0;
  }
  else {
    FUN_01406bf3(DVar4);
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2003 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((_File->_flag & 0x83U) != 0) && ((_File->_flag & 8U) != 0)) {
    FUN_01404c4e(_File->_base);
    *(ushort *)&_File->_flag = *(ushort *)&_File->_flag & 0xfbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



int __cdecl FUN_01405da0(int *param_1)

{
  int iVar1;
  
  if (param_1 == (int *)0x0) {
    iVar1 = FUN_01405e62(0);
    return iVar1;
  }
  FUN_01405bf1((uint)param_1);
  iVar1 = FUN_01405dcf(param_1);
  FUN_01405c43((uint)param_1);
  return iVar1;
}



int __cdecl FUN_01405dcf(int *param_1)

{
  int iVar1;
  DWORD DVar2;
  
  iVar1 = FUN_01405dfd(param_1);
  if (iVar1 != 0) {
    return -1;
  }
  if ((*(byte *)((int)param_1 + 0xd) & 0x40) != 0) {
    DVar2 = FUN_01408d90(param_1[4]);
    return -(uint)(DVar2 != 0);
  }
  return 0;
}



undefined4 __cdecl FUN_01405dfd(int *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  
  uVar2 = 0;
  if ((((byte)param_1[3] & 3) == 2) && ((param_1[3] & 0x108U) != 0)) {
    uVar3 = *param_1 - (int)(char *)param_1[2];
    if (0 < (int)uVar3) {
      uVar1 = FUN_01408e23(param_1[4],(char *)param_1[2],uVar3);
      if (uVar1 == uVar3) {
        if ((param_1[3] & 0x80U) != 0) {
          param_1[3] = param_1[3] & 0xfffffffd;
        }
      }
      else {
        param_1[3] = param_1[3] | 0x20;
        uVar2 = 0xffffffff;
      }
    }
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return uVar2;
}



int __cdecl FUN_01405e62(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = 0;
  iVar5 = 0;
  critical_code_area_executor(2);
  iVar4 = 0;
  if (0 < DAT_01416fe0) {
    do {
      iVar2 = *(int *)(DAT_01415fcc + iVar4 * 4);
      if ((iVar2 != 0) && ((*(byte *)(iVar2 + 0xc) & 0x83) != 0)) {
        FUN_01405c20(iVar4,iVar2);
        piVar1 = *(int **)(DAT_01415fcc + iVar4 * 4);
        if ((piVar1[3] & 0x83U) != 0) {
          if (param_1 == 1) {
            iVar2 = FUN_01405dcf(piVar1);
            if (iVar2 != -1) {
              iVar3 = iVar3 + 1;
            }
          }
          else if ((param_1 == 0) && ((piVar1[3] & 2U) != 0)) {
            iVar2 = FUN_01405dcf(piVar1);
            if (iVar2 == -1) {
              iVar5 = -1;
            }
          }
        }
        FUN_01405c72(iVar4,*(int *)(DAT_01415fcc + iVar4 * 4));
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < DAT_01416fe0);
  }
  endCriticalFromID(2);
  if (param_1 != 1) {
    iVar3 = iVar5;
  }
  return iVar3;
}



uint __cdecl FUN_01405f06(byte **param_1)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  undefined *puVar4;
  
  pbVar3 = param_1[3];
  if ((((uint)pbVar3 & 0x83) != 0) && (((uint)pbVar3 & 0x40) == 0)) {
    if (((uint)pbVar3 & 2) == 0) {
      param_1[3] = (byte *)((uint)pbVar3 | 1);
      if (((uint)pbVar3 & 0x10c) == 0) {
        FUN_01409251(param_1);
      }
      else {
        *param_1 = param_1[2];
      }
      pbVar3 = (byte *)FUN_01409013((uint)param_1[4],(char *)param_1[2],(char *)param_1[6]);
      param_1[1] = pbVar3;
      if ((pbVar3 != (byte *)0x0) && (pbVar3 != (byte *)0xffffffff)) {
        if (((uint)param_1[3] & 0x82) == 0) {
          pbVar2 = param_1[4];
          if (pbVar2 == (byte *)0xffffffff) {
            puVar4 = &DAT_01413e78;
          }
          else {
            puVar4 = (undefined *)((&DAT_01415ec0)[(int)pbVar2 >> 5] + ((uint)pbVar2 & 0x1f) * 0x24)
            ;
          }
          if ((puVar4[4] & 0x82) == 0x82) {
            param_1[3] = (byte *)((uint)param_1[3] | 0x2000);
          }
        }
        if (((param_1[6] == (byte *)0x200) && (((uint)param_1[3] & 8) != 0)) &&
           (((uint)param_1[3] & 0x400) == 0)) {
          param_1[6] = (byte *)0x1000;
        }
        param_1[1] = pbVar3 + -1;
        bVar1 = **param_1;
        *param_1 = *param_1 + 1;
        return (uint)bVar1;
      }
      param_1[3] = (byte *)((uint)param_1[3] | (-(uint)(pbVar3 != (byte *)0x0) & 0x10) + 0x10);
      param_1[1] = (byte *)0x0;
    }
    else {
      param_1[3] = (byte *)((uint)pbVar3 | 0x20);
    }
  }
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_01405fe2(void **param_1)

{
  byte bVar1;
  undefined3 extraout_var;
  int iVar2;
  void *pvVar3;
  
  bVar1 = FUN_01409295((uint)param_1[4]);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    return 0;
  }
  if (param_1 == (void **)&DAT_014139f0) {
    iVar2 = 0;
  }
  else {
    if (param_1 != (void **)&DAT_01413a10) {
      return 0;
    }
    iVar2 = 1;
  }
  _DAT_014159c0 = _DAT_014159c0 + 1;
  if ((*(ushort *)(param_1 + 3) & 0x10c) != 0) {
    return 0;
  }
  if ((&DAT_014159c4)[iVar2] == 0) {
    pvVar3 = _malloc(0x1000);
    (&DAT_014159c4)[iVar2] = pvVar3;
    if (pvVar3 == (void *)0x0) {
      param_1[2] = param_1 + 5;
      *param_1 = param_1 + 5;
      param_1[6] = (void *)0x2;
      param_1[1] = (void *)0x2;
      goto LAB_0140605e;
    }
  }
  pvVar3 = (void *)(&DAT_014159c4)[iVar2];
  param_1[6] = (void *)0x1000;
  param_1[2] = pvVar3;
  *param_1 = pvVar3;
  param_1[1] = (void *)0x1000;
LAB_0140605e:
  *(ushort *)(param_1 + 3) = *(ushort *)(param_1 + 3) | 0x1102;
  return 1;
}



void __cdecl FUN_0140606f(int param_1,int *param_2)

{
  if ((param_1 != 0) && ((*(byte *)((int)param_2 + 0xd) & 0x10) != 0)) {
    FUN_01405dfd(param_2);
    *(byte *)((int)param_2 + 0xd) = *(byte *)((int)param_2 + 0xd) & 0xee;
    param_2[6] = 0;
    *param_2 = 0;
    param_2[2] = 0;
  }
  return;
}



int __cdecl FUN_01406099(char **param_1,byte *param_2,undefined4 *param_3)

{
  int iVar1;
  uint uVar2;
  WCHAR *pWVar3;
  WCHAR *pWVar4;
  undefined4 uVar5;
  short *psVar6;
  int *piVar7;
  LPSTR pCVar8;
  byte bVar9;
  int iVar10;
  uint uVar11;
  LPSTR pCVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  ulonglong uVar15;
  undefined local_24c [511];
  undefined local_4d;
  undefined4 local_4c;
  undefined4 local_48;
  uint local_44;
  uint local_40;
  CHAR local_3c [4];
  undefined4 local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20;
  char local_1a;
  char local_19;
  int local_18;
  int local_14;
  LPSTR local_10;
  WCHAR *local_c;
  uint local_8;
  
  local_34 = 0;
  bVar9 = *param_2;
  param_2 = param_2 + 1;
  local_10 = (LPSTR)0x0;
  local_18 = 0;
  do {
    if ((bVar9 == 0) || (local_18 < 0)) {
      return local_18;
    }
    if (((char)bVar9 < ' ') || ('x' < (char)bVar9)) {
      uVar2 = 0;
    }
    else {
      uVar2 = (byte)(&DAT_0140f290)[(char)bVar9] & 0xf;
    }
    local_34 = (int)(char)(&DAT_0140f2b0)[uVar2 * 8 + local_34] >> 4;
    switch(local_34) {
    case 0:
switchD_01406107_caseD_0:
      local_28 = 0;
      if ((PTR_DAT_014137b8[(uint)bVar9 * 2 + 1] & 0x80) != 0) {
        FUN_014067da((int)(char)bVar9,param_1,&local_18);
        bVar9 = *param_2;
        param_2 = param_2 + 1;
      }
      FUN_014067da((int)(char)bVar9,param_1,&local_18);
      break;
    case 1:
      local_14 = -1;
      local_38 = 0;
      local_2c = 0;
      local_24 = 0;
      local_20 = 0;
      local_8 = 0;
      local_28 = 0;
      break;
    case 2:
      if (bVar9 == 0x20) {
        local_8 = local_8 | 2;
      }
      else if (bVar9 == 0x23) {
        local_8 = local_8 | 0x80;
      }
      else if (bVar9 == 0x2b) {
        local_8 = local_8 | 1;
      }
      else if (bVar9 == 0x2d) {
        local_8 = local_8 | 4;
      }
      else if (bVar9 == 0x30) {
        local_8 = local_8 | 8;
      }
      break;
    case 3:
      if (bVar9 == 0x2a) {
        local_24 = FUN_01406878((int *)&param_3);
        if (local_24 < 0) {
          local_8 = local_8 | 4;
          local_24 = -local_24;
        }
      }
      else {
        local_24 = (char)bVar9 + -0x30 + local_24 * 10;
      }
      break;
    case 4:
      local_14 = 0;
      break;
    case 5:
      if (bVar9 == 0x2a) {
        local_14 = FUN_01406878((int *)&param_3);
        if (local_14 < 0) {
          local_14 = -1;
        }
      }
      else {
        local_14 = (char)bVar9 + -0x30 + local_14 * 10;
      }
      break;
    case 6:
      if (bVar9 == 0x49) {
        if ((*param_2 != 0x36) || (param_2[1] != 0x34)) {
          local_34 = 0;
          goto switchD_01406107_caseD_0;
        }
        param_2 = param_2 + 2;
        local_8 = local_8 | 0x8000;
      }
      else if (bVar9 == 0x68) {
        local_8 = local_8 | 0x20;
      }
      else if (bVar9 == 0x6c) {
        local_8 = local_8 | 0x10;
      }
      else if (bVar9 == 0x77) {
        local_8 = local_8 | 0x800;
      }
      break;
    case 7:
      pWVar4 = local_c;
      if ((char)bVar9 < 'h') {
        if ((char)bVar9 < 'e') {
          if ((char)bVar9 < 'Y') {
            if (bVar9 == 0x58) {
LAB_01406518:
              local_30 = 7;
LAB_0140651f:
              local_10 = (LPSTR)0x10;
              if ((local_8 & 0x80) != 0) {
                local_1a = '0';
                local_19 = (char)local_30 + 'Q';
                local_20 = 2;
              }
              goto LAB_01406589;
            }
            if (bVar9 != 0x43) {
              if ((bVar9 != 0x45) && (bVar9 != 0x47)) {
                if (bVar9 == 0x53) {
                  if ((local_8 & 0x830) == 0) {
                    local_8 = local_8 | 0x800;
                  }
                  goto LAB_014062c6;
                }
                goto LAB_014066a3;
              }
              local_38 = 1;
              bVar9 = bVar9 + 0x20;
              goto LAB_01406327;
            }
            if ((local_8 & 0x830) == 0) {
              local_8 = local_8 | 0x800;
            }
LAB_01406354:
            if ((local_8 & 0x810) == 0) {
              uVar5 = FUN_01406878((int *)&param_3);
              local_24c[0] = (char)uVar5;
              local_10 = (LPSTR)0x1;
            }
            else {
              uVar5 = FUN_01406895((int *)&param_3);
              local_10 = FUN_014092be(local_24c,(WCHAR)uVar5);
              if ((int)local_10 < 0) {
                local_2c = 1;
              }
            }
            pWVar4 = (WCHAR *)local_24c;
          }
          else if (bVar9 == 0x5a) {
            psVar6 = (short *)FUN_01406878((int *)&param_3);
            if ((psVar6 == (short *)0x0) ||
               (pWVar4 = *(WCHAR **)(psVar6 + 2), pWVar4 == (WCHAR *)0x0)) {
              local_c = (WCHAR *)PTR_s__null__01413c50;
              pWVar4 = (WCHAR *)PTR_s__null__01413c50;
              goto LAB_01406499;
            }
            if ((local_8 & 0x800) == 0) {
              local_28 = 0;
              local_10 = (LPSTR)(int)*psVar6;
            }
            else {
              local_28 = 1;
              local_10 = (LPSTR)((uint)(int)*psVar6 >> 1);
            }
          }
          else {
            if (bVar9 == 99) goto LAB_01406354;
            if (bVar9 == 100) goto LAB_0140657e;
          }
        }
        else {
LAB_01406327:
          local_8 = local_8 | 0x40;
          pWVar4 = (WCHAR *)local_24c;
          if (local_14 < 0) {
            local_14 = 6;
          }
          else if ((local_14 == 0) && (bVar9 == 0x67)) {
            local_14 = 1;
          }
          local_4c = *param_3;
          local_48 = param_3[1];
          param_3 = param_3 + 2;
          local_c = pWVar4;
          (*(code *)PTR_FUN_01413f30)(&local_4c,local_24c,(int)(char)bVar9,local_14,local_38);
          uVar2 = local_8 & 0x80;
          if ((uVar2 != 0) && (local_14 == 0)) {
            (*(code *)PTR_FUN_01413f3c)(local_24c);
          }
          if ((bVar9 == 0x67) && (uVar2 == 0)) {
            (*(code *)PTR_FUN_01413f34)(local_24c);
          }
          if (local_24c[0] == '-') {
            local_8 = local_8 | 0x100;
            pWVar4 = (WCHAR *)(local_24c + 1);
            local_c = pWVar4;
          }
LAB_01406499:
          local_10 = (LPSTR)_strlen((char *)pWVar4);
          pWVar4 = local_c;
        }
      }
      else {
        if (bVar9 == 0x69) {
LAB_0140657e:
          local_8 = local_8 | 0x40;
        }
        else {
          if (bVar9 == 0x6e) {
            piVar7 = (int *)FUN_01406878((int *)&param_3);
            if ((local_8 & 0x20) == 0) {
              *piVar7 = local_18;
            }
            else {
              *(undefined2 *)piVar7 = (undefined2)local_18;
            }
            local_2c = 1;
            break;
          }
          if (bVar9 == 0x6f) {
            local_10 = (LPSTR)0x8;
            if ((local_8 & 0x80) != 0) {
              local_8 = local_8 | 0x200;
            }
            goto LAB_01406589;
          }
          if (bVar9 == 0x70) {
            local_14 = 8;
            goto LAB_01406518;
          }
          if (bVar9 == 0x73) {
LAB_014062c6:
            iVar10 = local_14;
            if (local_14 == -1) {
              iVar10 = 0x7fffffff;
            }
            pWVar3 = (WCHAR *)FUN_01406878((int *)&param_3);
            if ((local_8 & 0x810) == 0) {
              pWVar4 = pWVar3;
              if (pWVar3 == (WCHAR *)0x0) {
                pWVar3 = (WCHAR *)PTR_s__null__01413c50;
                pWVar4 = (WCHAR *)PTR_s__null__01413c50;
              }
              for (; (iVar10 != 0 && (*(char *)pWVar3 != '\0')); pWVar3 = (WCHAR *)((int)pWVar3 + 1)
                  ) {
                iVar10 = iVar10 + -1;
              }
              local_10 = (LPSTR)((int)pWVar3 - (int)pWVar4);
            }
            else {
              if (pWVar3 == (WCHAR *)0x0) {
                pWVar3 = (WCHAR *)PTR_DAT_01413c54;
              }
              local_28 = 1;
              for (pWVar4 = pWVar3; (iVar10 != 0 && (*pWVar4 != L'\0')); pWVar4 = pWVar4 + 1) {
                iVar10 = iVar10 + -1;
              }
              local_10 = (LPSTR)((int)pWVar4 - (int)pWVar3 >> 1);
              pWVar4 = pWVar3;
            }
            goto LAB_014066a3;
          }
          if (bVar9 != 0x75) {
            if (bVar9 != 0x78) goto LAB_014066a3;
            local_30 = 0x27;
            goto LAB_0140651f;
          }
        }
        local_10 = (LPSTR)0xa;
LAB_01406589:
        if ((local_8 & 0x8000) == 0) {
          if ((local_8 & 0x20) == 0) {
            if ((local_8 & 0x40) == 0) {
              uVar2 = FUN_01406878((int *)&param_3);
              uVar13 = (ulonglong)uVar2;
              goto LAB_014065dc;
            }
            uVar2 = FUN_01406878((int *)&param_3);
          }
          else if ((local_8 & 0x40) == 0) {
            uVar2 = FUN_01406878((int *)&param_3);
            uVar2 = uVar2 & 0xffff;
          }
          else {
            uVar5 = FUN_01406878((int *)&param_3);
            uVar2 = (uint)(short)uVar5;
          }
          uVar13 = (ulonglong)(int)uVar2;
        }
        else {
          uVar13 = FUN_01406885((int *)&param_3);
        }
LAB_014065dc:
        iVar10 = (int)(uVar13 >> 0x20);
        if ((((local_8 & 0x40) != 0) && (iVar10 == 0 || (longlong)uVar13 < 0)) &&
           ((longlong)uVar13 < 0)) {
          local_8 = local_8 | 0x100;
          uVar13 = CONCAT44(-(iVar10 + (uint)((int)uVar13 != 0)),-(int)uVar13);
        }
        uVar2 = (uint)(uVar13 >> 0x20);
        uVar15 = uVar13 & 0xffffffff;
        if ((local_8 & 0x8000) == 0) {
          uVar2 = 0;
        }
        if (local_14 < 0) {
          local_14 = 1;
        }
        else {
          local_8 = local_8 & 0xfffffff7;
        }
        if (((uint)uVar13 | uVar2) == 0) {
          local_20 = 0;
        }
        local_c = (WCHAR *)&local_4d;
        while( true ) {
          uVar11 = (uint)uVar15;
          iVar10 = local_14 + -1;
          if ((local_14 < 1) && ((uVar11 | uVar2) == 0)) break;
          local_40 = (int)local_10 >> 0x1f;
          local_44 = (uint)local_10;
          local_14 = iVar10;
          uVar14 = __aullrem(uVar11,uVar2,(uint)local_10,local_40);
          iVar10 = (int)uVar14 + 0x30;
          uVar15 = __aulldiv(uVar11,uVar2,local_44,local_40);
          uVar2 = (uint)(uVar15 >> 0x20);
          if (0x39 < iVar10) {
            iVar10 = iVar10 + local_30;
          }
          pWVar4 = (WCHAR *)((int)local_c + -1);
          *(char *)local_c = (char)iVar10;
          local_c = pWVar4;
        }
        iVar1 = -(int)local_c;
        local_10 = &local_4d + iVar1;
        pWVar4 = (WCHAR *)((int)local_c + 1);
        local_14 = iVar10;
        if (((local_8 & 0x200) != 0) && ((*(char *)pWVar4 != '0' || (local_10 == (LPSTR)0x0)))) {
          *(char *)local_c = '0';
          local_10 = (LPSTR)((int)&local_4c + iVar1);
          pWVar4 = local_c;
        }
      }
LAB_014066a3:
      local_c = pWVar4;
      uVar2 = local_8;
      if (local_2c == 0) {
        if ((local_8 & 0x40) != 0) {
          if ((local_8 & 0x100) == 0) {
            if ((local_8 & 1) == 0) {
              if ((local_8 & 2) == 0) goto LAB_014066db;
              local_1a = ' ';
            }
            else {
              local_1a = '+';
            }
          }
          else {
            local_1a = '-';
          }
          local_20 = 1;
        }
LAB_014066db:
        iVar10 = (local_24 - local_20) - (int)local_10;
        if ((local_8 & 0xc) == 0) {
          FUN_0140680f(0x20,iVar10,param_1,&local_18);
        }
        FUN_01406840(&local_1a,local_20,param_1,&local_18);
        if (((uVar2 & 8) != 0) && ((uVar2 & 4) == 0)) {
          FUN_0140680f(0x30,iVar10,param_1,&local_18);
        }
        if ((local_28 == 0) || (pCVar12 = local_10, pWVar4 = local_c, (int)local_10 < 1)) {
          FUN_01406840((char *)local_c,(int)local_10,param_1,&local_18);
        }
        else {
          do {
            pCVar12 = pCVar12 + -1;
            pCVar8 = FUN_014092be(local_3c,*pWVar4);
            if ((int)pCVar8 < 1) break;
            FUN_01406840(local_3c,(int)pCVar8,param_1,&local_18);
            pWVar4 = pWVar4 + 1;
          } while (pCVar12 != (LPSTR)0x0);
        }
        if ((local_8 & 4) != 0) {
          FUN_0140680f(0x20,iVar10,param_1,&local_18);
        }
      }
    }
    bVar9 = *param_2;
    param_2 = param_2 + 1;
  } while( true );
}



void __cdecl FUN_014067da(uint param_1,char **param_2,int *param_3)

{
  char **ppcVar1;
  uint uVar2;
  
  ppcVar1 = param_2 + 1;
  *ppcVar1 = *ppcVar1 + -1;
  if ((int)*ppcVar1 < 0) {
    uVar2 = FUN_01406adb(param_1,param_2);
  }
  else {
    **param_2 = (char)param_1;
    *param_2 = *param_2 + 1;
    uVar2 = param_1 & 0xff;
  }
  if (uVar2 == 0xffffffff) {
    *param_3 = -1;
    return;
  }
  *param_3 = *param_3 + 1;
  return;
}



void __cdecl FUN_0140680f(uint param_1,int param_2,char **param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      FUN_014067da(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void __cdecl FUN_01406840(char *param_1,int param_2,char **param_3,int *param_4)

{
  char cVar1;
  
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_014067da((int)cVar1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



undefined4 __cdecl FUN_01406878(int *param_1)

{
  *param_1 = *param_1 + 4;
  return *(undefined4 *)(*param_1 + -4);
}



undefined8 __cdecl FUN_01406885(int *param_1)

{
  *param_1 = *param_1 + 8;
  return *(undefined8 *)(*param_1 + -8);
}



undefined4 __cdecl FUN_01406895(int *param_1)

{
  *param_1 = *param_1 + 4;
  return CONCAT22((short)((uint)*param_1 >> 0x10),*(undefined2 *)(*param_1 + -4));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_014068a3(LPCSTR param_1,char *param_2,uint param_3,undefined4 *param_4)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  uint uVar6;
  
  bVar4 = false;
  bVar3 = false;
  cVar1 = *param_2;
  if (cVar1 == 'a') {
    uVar5 = 0x109;
  }
  else {
    if (cVar1 == 'r') {
      uVar5 = 0;
      uVar6 = DAT_01415ae4 | 1;
      goto LAB_014068e4;
    }
    if (cVar1 != 'w') {
      return (undefined4 *)0x0;
    }
    uVar5 = 0x301;
  }
  uVar6 = DAT_01415ae4 | 2;
LAB_014068e4:
  bVar2 = true;
LAB_014068e7:
  cVar1 = param_2[1];
  param_2 = param_2 + 1;
  if ((cVar1 == '\0') || (!bVar2)) {
    uVar5 = FUN_0140947c(param_1,uVar5,param_3,0x1a4);
    if ((int)uVar5 < 0) {
      return (undefined4 *)0x0;
    }
    _DAT_014159c0 = _DAT_014159c0 + 1;
    param_4[3] = uVar6;
    param_4[1] = 0;
    *param_4 = 0;
    param_4[2] = 0;
    param_4[7] = 0;
    param_4[4] = uVar5;
    return param_4;
  }
  if (cVar1 < 'U') {
    if (cVar1 == 'T') {
      if ((uVar5 & 0x1000) == 0) {
        uVar5 = uVar5 | 0x1000;
        goto LAB_014068e7;
      }
    }
    else if (cVar1 == '+') {
      if ((uVar5 & 2) == 0) {
        uVar5 = uVar5 & 0xfffffffe | 2;
        uVar6 = uVar6 & 0xfffffffc | 0x80;
        goto LAB_014068e7;
      }
    }
    else if (cVar1 == 'D') {
      if ((uVar5 & 0x40) == 0) {
        uVar5 = uVar5 | 0x40;
        goto LAB_014068e7;
      }
    }
    else if (cVar1 == 'R') {
      if (!bVar3) {
        bVar3 = true;
        uVar5 = uVar5 | 0x10;
        goto LAB_014068e7;
      }
    }
    else if ((cVar1 == 'S') && (!bVar3)) {
      bVar3 = true;
      uVar5 = uVar5 | 0x20;
      goto LAB_014068e7;
    }
  }
  else {
    if (cVar1 == 'b') {
      if ((uVar5 & 0xc000) != 0) goto LAB_014069c7;
      uVar5 = uVar5 | 0x8000;
      goto LAB_014068e7;
    }
    if (cVar1 == 'c') {
      if (!bVar4) {
        bVar4 = true;
        uVar6 = uVar6 | 0x4000;
        goto LAB_014068e7;
      }
    }
    else {
      if (cVar1 != 'n') {
        if ((cVar1 != 't') || ((uVar5 & 0xc000) != 0)) goto LAB_014069c7;
        uVar5 = uVar5 | 0x4000;
        goto LAB_014068e7;
      }
      if (!bVar4) {
        bVar4 = true;
        uVar6 = uVar6 & 0xffffbfff;
        goto LAB_014068e7;
      }
    }
  }
LAB_014069c7:
  bVar2 = false;
  goto LAB_014068e7;
}



undefined4 * FUN_01406a13(void)

{
  int iVar1;
  void *pvVar2;
  int iVar3;
  undefined4 *puVar4;
  
  puVar4 = (undefined4 *)0x0;
  critical_code_area_executor(2);
  iVar3 = 0;
  if (0 < DAT_01416fe0) {
    do {
      iVar1 = *(int *)(DAT_01415fcc + iVar3 * 4);
      if (iVar1 == 0) {
        iVar3 = iVar3 * 4;
        pvVar2 = _malloc(0x38);
        *(void **)(iVar3 + DAT_01415fcc) = pvVar2;
        if (*(int *)(iVar3 + DAT_01415fcc) != 0) {
          InitializeCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar3 + DAT_01415fcc) + 0x20));
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar3 + DAT_01415fcc) + 0x20));
          puVar4 = *(undefined4 **)(iVar3 + DAT_01415fcc);
LAB_01406ab7:
          if (puVar4 != (undefined4 *)0x0) {
            puVar4[4] = 0xffffffff;
            puVar4[1] = 0;
            puVar4[3] = 0;
            puVar4[2] = 0;
            *puVar4 = 0;
            puVar4[7] = 0;
          }
        }
        break;
      }
      if ((*(byte *)(iVar1 + 0xc) & 0x83) == 0) {
        FUN_01405c20(iVar3,iVar1);
        iVar1 = *(int *)(DAT_01415fcc + iVar3 * 4);
        if ((*(byte *)(iVar1 + 0xc) & 0x83) == 0) {
          puVar4 = *(undefined4 **)(DAT_01415fcc + iVar3 * 4);
          goto LAB_01406ab7;
        }
        FUN_01405c72(iVar3,iVar1);
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < DAT_01416fe0);
  }
  endCriticalFromID(2);
  return puVar4;
}



uint __cdecl FUN_01406adb(uint param_1,char **param_2)

{
  char *pcVar1;
  char *pcVar2;
  char **ppcVar3;
  byte bVar4;
  undefined3 extraout_var;
  undefined *puVar5;
  char **ppcVar6;
  
  ppcVar3 = param_2;
  pcVar1 = param_2[3];
  pcVar2 = param_2[4];
  if ((((uint)pcVar1 & 0x82) == 0) || (((uint)pcVar1 & 0x40) != 0)) {
LAB_01406be7:
    param_2[3] = (char *)((uint)pcVar1 | 0x20);
  }
  else {
    if (((uint)pcVar1 & 1) != 0) {
      param_2[1] = (char *)0x0;
      if (((uint)pcVar1 & 0x10) == 0) goto LAB_01406be7;
      *param_2 = param_2[2];
      param_2[3] = (char *)((uint)pcVar1 & 0xfffffffe);
    }
    pcVar1 = param_2[3];
    param_2[1] = (char *)0x0;
    param_2 = (char **)0x0;
    ppcVar3[3] = (char *)((uint)pcVar1 & 0xffffffef | 2);
    if ((((uint)pcVar1 & 0x10c) == 0) &&
       (((ppcVar3 != (char **)&DAT_014139f0 && (ppcVar3 != (char **)&DAT_01413a10)) ||
        (bVar4 = FUN_01409295((uint)pcVar2), CONCAT31(extraout_var,bVar4) == 0)))) {
      FUN_01409251(ppcVar3);
    }
    if ((*(ushort *)(ppcVar3 + 3) & 0x108) == 0) {
      ppcVar6 = (char **)0x1;
      param_2 = (char **)FUN_01408e23((uint)pcVar2,(char *)&param_1,1);
    }
    else {
      pcVar1 = ppcVar3[2];
      ppcVar6 = (char **)(*ppcVar3 + -(int)pcVar1);
      *ppcVar3 = pcVar1 + 1;
      ppcVar3[1] = ppcVar3[6] + -1;
      if ((int)ppcVar6 < 1) {
        if (pcVar2 == (char *)0xffffffff) {
          puVar5 = &DAT_01413e78;
        }
        else {
          puVar5 = (undefined *)((&DAT_01415ec0)[(int)pcVar2 >> 5] + ((uint)pcVar2 & 0x1f) * 0x24);
        }
        if ((puVar5[4] & 0x20) != 0) {
          FUN_0140974b((uint)pcVar2,0,2);
        }
      }
      else {
        param_2 = (char **)FUN_01408e23((uint)pcVar2,pcVar1,(uint)ppcVar6);
      }
      *ppcVar3[2] = (char)param_1;
    }
    if (param_2 == ppcVar6) {
      return param_1 & 0xff;
    }
    ppcVar3[3] = (char *)((uint)ppcVar3[3] | 0x20);
  }
  return 0xffffffff;
}



void __cdecl FUN_01406bf3(uint param_1)

{
  DWORD *pDVar1;
  uint *puVar2;
  int iVar3;
  
  pDVar1 = FUN_01406c6f();
  iVar3 = 0;
  *pDVar1 = param_1;
  puVar2 = &DAT_01413c58;
  do {
    if (param_1 == *puVar2) {
      pDVar1 = FUN_01406c66();
      *pDVar1 = (&DAT_01413c5c)[iVar3 * 2];
      return;
    }
    puVar2 = puVar2 + 2;
    iVar3 = iVar3 + 1;
  } while ((int)puVar2 < 0x1413dc0);
  if ((0x12 < param_1) && (param_1 < 0x25)) {
    pDVar1 = FUN_01406c66();
    *pDVar1 = 0xd;
    return;
  }
  if ((0xbb < param_1) && (param_1 < 0xcb)) {
    pDVar1 = FUN_01406c66();
    *pDVar1 = 8;
    return;
  }
  pDVar1 = FUN_01406c66();
  *pDVar1 = 0x16;
  return;
}



DWORD * FUN_01406c66(void)

{
  DWORD *pDVar1;
  
  pDVar1 = FUN_01408431();
  return pDVar1 + 2;
}



DWORD * FUN_01406c6f(void)

{
  DWORD *pDVar1;
  
  pDVar1 = FUN_01408431();
  return pDVar1 + 3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl
ConvertSystemTimeToTimeT(int iYear,int iMonth,int iDay,int iHour,int iMinute,int iSecond,int iDST)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  uint iTimeT;
  int iVar3;
  int local_28 [2];
  int local_20;
  int local_18;
  uint local_14;
  int local_c;
  
  iTimeT = iYear - 0x76c;
  if (((int)iTimeT < 0x46) || (0x8a < (int)iTimeT)) {
    iVar2 = -1;
  }
  else {
    iVar3 = *(int *)(&DAT_01414034 + iMonth * 4) + iDay;
    if (((iTimeT & 3) == 0) && (2 < iMonth)) {
      iVar3 = iVar3 + 1;
    }
    InitializeCriticalSection();
    local_20 = iHour;
    local_18 = iMonth + -1;
    iVar2 = ((iHour + (iTimeT * 0x16d + iVar3 + (iYear + -0x76d >> 2)) * 0x18) * 0x3c + iMinute) *
            0x3c + DAT_01413f50 + 0x7c558180 + iSecond;
    if ((iDST == 1) ||
       (((iDST == -1 && (DAT_01413f54 != 0)) &&
        (local_14 = iTimeT, local_c = iVar3, bVar1 = FUN_01409aee(local_28),
        CONCAT31(extraout_var,bVar1) != 0)))) {
      iVar2 = iVar2 + _DAT_01413f58;
    }
  }
  return iVar2;
}



void __cdecl FUN_01406d3a(undefined4 *param_1)

{
  int iVar1;
  HMODULE pHVar2;
  
  *param_1 = 0;
  pHVar2 = GetModuleHandleA((LPCSTR)0x0);
  if ((*(short *)&pHVar2->unused == 0x5a4d) && (iVar1 = pHVar2[0xf].unused, iVar1 != 0)) {
    *(undefined *)param_1 = *(undefined *)((int)&pHVar2[6].unused + iVar1 + 2);
    *(undefined *)((int)param_1 + 1) = *(undefined *)((int)&pHVar2[6].unused + iVar1 + 3);
  }
  return;
}



int FUN_01406d67(void)

{
  char cVar1;
  byte bVar2;
  BOOL BVar3;
  int iVar4;
  DWORD DVar5;
  uint *puVar6;
  byte *pbVar7;
  undefined4 *puVar8;
  char *pcVar9;
  byte *this;
  undefined4 unaff_EBX;
  undefined1 unaff_BP;
  undefined4 local_1230;
  char local_1a0 [260];
  DWORD local_9c;
  uint local_98;
  DWORD local_8c;
  undefined4 uStackY_18;
  byte bVar10;
  
  FUN_014028c0(unaff_BP);
  local_9c = 0x94;
  BVar3 = GetVersionExA((LPOSVERSIONINFOA)&local_9c);
  if (((BVar3 == 0) || (local_8c != 2)) || (local_98 < 5)) {
    uStackY_18._0_1_ = -0x3f;
    uStackY_18._1_1_ = 'm';
    uStackY_18._2_1_ = '@';
    uStackY_18._3_1_ = '\x01';
    DVar5 = GetEnvironmentVariableA("__MSVCRT_HEAP_SELECT",(LPSTR)&local_1230,0x1090);
    bVar10 = (byte)unaff_EBX;
    if (DVar5 != 0) {
      puVar8 = &local_1230;
      while ((char)local_1230 != '\0') {
        cVar1 = *(char *)puVar8;
        if (('`' < cVar1) && (cVar1 < '{')) {
          *(char *)puVar8 = cVar1 + -0x20;
        }
        puVar8 = (undefined4 *)((int)puVar8 + 1);
        local_1230._0_1_ = *(char *)puVar8;
      }
      uStackY_18._0_1_ = -1;
      uStackY_18._1_1_ = 'm';
      uStackY_18._2_1_ = '@';
      uStackY_18._3_1_ = '\x01';
      iVar4 = _strncmp("__GLOBAL_HEAP_SELECTED",(char *)&local_1230,0x16);
      bVar10 = (byte)unaff_EBX;
      if (iVar4 == 0) {
        puVar6 = &local_1230;
      }
      else {
        uStackY_18._0_1_ = '!';
        uStackY_18._1_1_ = 'n';
        uStackY_18._2_1_ = '@';
        uStackY_18._3_1_ = '\x01';
        GetModuleFileNameA((HMODULE)0x0,local_1a0,0x104);
        bVar10 = (byte)unaff_EBX;
        pcVar9 = local_1a0;
        while (local_1a0[0] != '\0') {
          cVar1 = *pcVar9;
          if (('`' < cVar1) && (cVar1 < '{')) {
            *pcVar9 = cVar1 + -0x20;
          }
          bVar10 = (byte)unaff_EBX;
          pcVar9 = pcVar9 + 1;
          local_1a0[0] = *pcVar9;
        }
        puVar6 = FUN_01402e10(&local_1230,local_1a0);
      }
      if ((puVar6 != (uint *)0x0) && (puVar6 = FUN_014031d0(puVar6,','), puVar6 != (uint *)0x0)) {
        pbVar7 = (byte *)((int)puVar6 + 1);
        bVar2 = *pbVar7;
        this = pbVar7;
        while (bVar2 != 0) {
          if (*this == 0x3b) {
            *this = 0;
          }
          else {
            this = this + 1;
          }
          bVar2 = *this;
        }
        uStackY_18._0_1_ = -0x79;
        uStackY_18._1_1_ = 'n';
        uStackY_18._2_1_ = '@';
        uStackY_18._3_1_ = '\x01';
        iVar4 = FUN_01409dfb(this,pbVar7,(byte **)0x0,(undefined *)0xa);
        if (iVar4 == 2) {
          return 2;
        }
        if (iVar4 == 3) {
          return 3;
        }
        if (iVar4 == 1) {
          return 1;
        }
      }
    }
    FUN_01406d3a((undefined4 *)&stack0xfffffff8);
    iVar4 = 3 - (uint)(bVar10 < 6);
  }
  else {
    iVar4 = 1;
  }
  return iVar4;
}



undefined4 __cdecl FUN_01406eaf(int param_1)

{
  undefined **ppuVar1;
  
  DAT_01415fc4 = HeapCreate((uint)(param_1 == 0),0x1000,0);
  if (DAT_01415fc4 != (HANDLE)0x0) {
    DAT_01415fc8 = FUN_01406d67();
    if (DAT_01415fc8 == 3) {
      ppuVar1 = (undefined **)FUN_014033b0(0x3f8);
    }
    else {
      if (DAT_01415fc8 != 2) {
        return 1;
      }
      ppuVar1 = FUN_01404319();
    }
    if (ppuVar1 != (undefined **)0x0) {
      return 1;
    }
    HeapDestroy(DAT_01415fc4);
  }
  return 0;
}



undefined4 * __cdecl FUN_01406fc0(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_01407177_caseD_2;
        case 3:
          goto switchD_01407177_caseD_3;
        }
        goto switchD_01407177_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_01407177_caseD_0;
      case 1:
        goto switchD_01407177_caseD_1;
      case 2:
        goto switchD_01407177_caseD_2;
      case 3:
        goto switchD_01407177_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_01407177_caseD_2;
            case 3:
              goto switchD_01407177_caseD_3;
            }
            goto switchD_01407177_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_01407177_caseD_2;
            case 3:
              goto switchD_01407177_caseD_3;
            }
            goto switchD_01407177_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_01407177_caseD_2;
            case 3:
              goto switchD_01407177_caseD_3;
            }
            goto switchD_01407177_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_01407177_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_01407177_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_01407177_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_01407177_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_01406ff5_caseD_2;
      case 3:
        goto switchD_01406ff5_caseD_3;
      }
      goto switchD_01406ff5_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_01406ff5_caseD_0;
    case 1:
      goto switchD_01406ff5_caseD_1;
    case 2:
      goto switchD_01406ff5_caseD_2;
    case 3:
      goto switchD_01406ff5_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_01406ff5_caseD_2;
          case 3:
            goto switchD_01406ff5_caseD_3;
          }
          goto switchD_01406ff5_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_01406ff5_caseD_2;
          case 3:
            goto switchD_01406ff5_caseD_3;
          }
          goto switchD_01406ff5_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_01406ff5_caseD_2;
          case 3:
            goto switchD_01406ff5_caseD_3;
          }
          goto switchD_01406ff5_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar1) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_01406ff5_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_01406ff5_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_01406ff5_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_01406ff5_caseD_0:
  return param_1;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x1407310,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual
// Studio 2003 Release

void __cdecl __local_unwind2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_01407318;
  uStack_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_014073ce();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  *unaff_FS_OFFSET = uStack_1c;
  return;
}



void FUN_014073ce(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_01413dd8 = *(undefined4 *)(unaff_EBP + 8);
  DAT_01413dd4 = in_EAX;
  DAT_01413ddc = unaff_EBP;
  return;
}



void FUN_014074ad(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



undefined4 __cdecl CheckMemoryAllocation(int mem_size)

{
  int mem_check;
  
  if (memoryAllocatorFunction != (code *)0x0) {
    mem_check = (*memoryAllocatorFunction)(mem_size);
    if (mem_check != 0) {
      return 1;
    }
  }
  return 0;
}



uint __thiscall FUN_0140750d(void *this,byte *param_1,byte *param_2)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  byte *pbVar5;
  ushort uVar6;
  ushort uVar7;
  byte *local_10;
  byte *local_c;
  byte local_8;
  byte local_7;
  
  if (DAT_01415c8c == 0) {
    uVar3 = FUN_0140a6c0(this,param_1,param_2);
  }
  else {
    critical_code_area_executor(0x19);
    local_10 = param_2 + -1;
    local_c = param_1 + -1;
    do {
      uVar3 = (uint)*param_1;
      pbVar5 = param_1 + 1;
      pbVar1 = local_c + 1;
      if (((&DAT_01415da1)[uVar3] & 4) == 0) {
        param_1 = pbVar5;
        local_c = pbVar1;
        if (((&DAT_01415da1)[uVar3] & 0x10) == 0x10) {
          uVar3 = (uint)(byte)(&DAT_01415ca0)[uVar3];
        }
      }
      else if (*pbVar5 == 0) {
        uVar3 = 0;
        param_1 = pbVar5;
        local_c = pbVar1;
      }
      else {
        iVar4 = FUN_0140a46c(DAT_01415ea4,0x200,(char *)pbVar1,2,(LPWSTR)&local_8,2,DAT_01415c78,1);
        if (iVar4 == 1) {
          uVar3 = (uint)local_8;
        }
        else {
          if (iVar4 != 2) goto LAB_01407671;
          uVar3 = (uint)local_8 * 0x100 + (uint)local_7;
        }
        param_1 = param_1 + 2;
        local_c = local_c + 2;
      }
      bVar2 = *param_2;
      uVar6 = (ushort)bVar2;
      pbVar5 = param_2 + 1;
      pbVar1 = local_10 + 1;
      if (((&DAT_01415da1)[bVar2] & 4) == 0) {
        param_2 = pbVar5;
        local_10 = pbVar1;
        if (((&DAT_01415da1)[bVar2] & 0x10) == 0x10) {
          uVar6 = (ushort)(byte)(&DAT_01415ca0)[bVar2];
        }
      }
      else if (*pbVar5 == 0) {
        uVar6 = 0;
        param_2 = pbVar5;
        local_10 = pbVar1;
      }
      else {
        iVar4 = FUN_0140a46c(DAT_01415ea4,0x200,(char *)pbVar1,2,(LPWSTR)&local_8,2,DAT_01415c78,1);
        if (iVar4 == 1) {
          uVar6 = (ushort)local_8;
        }
        else {
          if (iVar4 != 2) {
LAB_01407671:
            endCriticalFromID(0x19);
            return 0x7fffffff;
          }
          uVar6 = (ushort)local_8 * 0x100 + (ushort)local_7;
        }
        param_2 = param_2 + 2;
        local_10 = local_10 + 2;
      }
      uVar7 = (ushort)uVar3;
      if (uVar7 != uVar6) {
        endCriticalFromID(0x19);
        return (-(uint)(uVar6 < uVar7) & 2) - 1;
      }
    } while (uVar7 != 0);
    endCriticalFromID(0x19);
    uVar3 = 0;
  }
  return uVar3;
}



byte * __cdecl FUN_014076a2(byte *param_1,uint param_2)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  byte bVar4;
  byte *pbVar5;
  bool bVar6;
  
  pbVar5 = (byte *)0x0;
  if (DAT_01415c8c == 0) {
    pbVar5 = (byte *)_strrchr((char *)param_1,param_2);
  }
  else {
    critical_code_area_executor(0x19);
    do {
      bVar4 = *param_1;
      if (((&DAT_01415da1)[bVar4] & 4) == 0) {
        bVar6 = param_2 == bVar4;
LAB_014076fd:
        pbVar3 = param_1;
        if (bVar6) {
          pbVar5 = param_1;
        }
      }
      else {
        bVar1 = param_1[1];
        pbVar3 = param_1 + 1;
        if (bVar1 == 0) {
          bVar6 = pbVar5 == (byte *)0x0;
          param_1 = pbVar3;
          bVar4 = bVar1;
          goto LAB_014076fd;
        }
        uVar2 = CONCAT11(bVar4,bVar1);
        bVar4 = bVar1;
        if (param_2 == uVar2) {
          pbVar5 = param_1;
        }
      }
      param_1 = pbVar3 + 1;
    } while (bVar4 != 0);
    endCriticalFromID(0x19);
  }
  return pbVar5;
}



uint * __cdecl FUN_01407714(uint *param_1,LPCSTR param_2,size_t param_3)

{
  LPCSTR lpFileName;
  uint *puVar1;
  DWORD *pDVar2;
  DWORD DVar3;
  
  lpFileName = param_2;
  if ((param_2 != (LPCSTR)0x0) && (*param_2 != '\0')) {
    puVar1 = param_1;
    if (param_1 == (uint *)0x0) {
      puVar1 = (uint *)_malloc(0x104);
      if (puVar1 == (uint *)0x0) {
        pDVar2 = FUN_01406c66();
        *pDVar2 = 0xc;
        return (uint *)0x0;
      }
      param_3 = 0x104;
    }
    DVar3 = GetFullPathNameA(lpFileName,param_3,(LPSTR)puVar1,&param_2);
    if (DVar3 < param_3) {
      if (DVar3 != 0) {
        return puVar1;
      }
      if (param_1 == (uint *)0x0) {
        FUN_01404c4e((undefined *)puVar1);
      }
      DVar3 = GetLastError();
      FUN_01406bf3(DVar3);
    }
    else {
      if (param_1 == (uint *)0x0) {
        FUN_01404c4e((undefined *)puVar1);
      }
      pDVar2 = FUN_01406c66();
      *pDVar2 = 0x22;
    }
    return (uint *)0x0;
  }
  puVar1 = FUN_0140a790(param_1,param_3);
  return puVar1;
}



int FUN_014077b9(void)

{
  DWORD DVar1;
  uint uVar2;
  int iVar3;
  byte local_108;
  char local_107;
  
  iVar3 = 0;
  DVar1 = GetCurrentDirectoryA(0x104,(LPSTR)&local_108);
  if ((DVar1 != 0) && (local_107 == ':')) {
    uVar2 = FUN_0140a8f4((uint)local_108);
    iVar3 = uVar2 - 0x40;
  }
  return iVar3;
}



undefined4 __cdecl FUN_014077fc(uint param_1)

{
  uint uVar1;
  uint uVar2;
  BOOL BVar3;
  DWORD DVar4;
  DWORD *pDVar5;
  undefined4 uVar6;
  
  uVar2 = param_1;
  if (((int)param_1 < 1) || (0x1f < (int)param_1)) {
    pDVar5 = FUN_01406c66();
    *pDVar5 = 0xd;
    pDVar5 = FUN_01406c6f();
    *pDVar5 = 0xf;
    uVar6 = 0xffffffff;
  }
  else {
    critical_code_area_executor(0xc);
    uVar1 = param_1 >> 0x10;
    param_1._0_2_ = CONCAT11(0x3a,(char)uVar2 + '@');
    param_1 = CONCAT22((short)uVar1,(undefined2)param_1) & 0xff00ffff;
    BVar3 = SetCurrentDirectoryA((LPCSTR)&param_1);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      FUN_01406bf3(DVar4);
      uVar6 = 0xffffffff;
    }
    else {
      uVar6 = 0;
    }
    endCriticalFromID(0xc);
  }
  return uVar6;
}



uint __cdecl FUN_0140786f(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined uVar5;
  undefined2 local_8;
  
  uVar4 = param_1;
  if (param_1 < 0x100) {
    if (((&DAT_01415da1)[param_1] & 0x10) == 0x10) {
      uVar4 = (uint)(byte)(&DAT_01415ca0)[param_1];
    }
  }
  else {
    uVar5 = (undefined)param_1;
    uVar2 = param_1 >> 8;
    uVar1 = param_1 >> 8;
    param_1 = CONCAT13(uVar5,CONCAT12((char)uVar1,(undefined2)param_1));
    if ((((&DAT_01415da1)[uVar2 & 0xff] & 4) != 0) &&
       (iVar3 = FUN_0140a46c(DAT_01415ea4,0x100,(char *)((int)&param_1 + 2),2,&local_8,2,
                             DAT_01415c78,1), iVar3 != 0)) {
      uVar4 = (uint)CONCAT11((undefined)local_8,local_8._1_1_);
    }
  }
  return uVar4;
}



byte * __cdecl FUN_014078ea(byte *param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  if (DAT_01415c8c == 0) {
    pbVar2 = FUN_0140aa30(param_1,param_2);
    return pbVar2;
  }
  critical_code_area_executor(0x19);
  bVar1 = *param_1;
  while (bVar1 != 0) {
    bVar1 = *param_2;
    pbVar2 = param_2;
    while (bVar1 != 0) {
      bVar1 = *pbVar2;
      if (((&DAT_01415da1)[bVar1] & 4) == 0) {
        pbVar3 = pbVar2;
        if (bVar1 == *param_1) break;
      }
      else if (((bVar1 == *param_1) && (pbVar2[1] == param_1[1])) ||
              (pbVar3 = pbVar2 + 1, pbVar2[1] == 0)) break;
      pbVar2 = pbVar3 + 1;
      bVar1 = *pbVar2;
    }
    if ((*pbVar2 != 0) ||
       ((((&DAT_01415da1)[*param_1] & 4) != 0 && (param_1 = param_1 + 1, *param_1 == 0)))) break;
    param_1 = param_1 + 1;
    bVar1 = *param_1;
  }
  endCriticalFromID(0x19);
  return (byte *)(-(uint)(*param_1 != 0) & (uint)param_1);
}



char * __cdecl FUN_0140797f(int param_1,uint *param_2,uint **param_3,uint **param_4)

{
  uint *puVar1;
  uint *puVar2;
  size_t sVar3;
  uint *puVar4;
  byte *pbVar5;
  int iVar6;
  undefined **ppuVar7;
  char *local_c;
  
  puVar1 = (uint *)FUN_014076a2((byte *)param_2,0x5c);
  puVar2 = (uint *)FUN_014076a2((byte *)param_2,0x2f);
  puVar4 = param_2;
  if (puVar2 == (uint *)0x0) {
    if ((puVar1 != (uint *)0x0) || (puVar1 = FUN_0140aab0(param_2,0x3a), puVar1 != (uint *)0x0))
    goto LAB_014079f4;
    sVar3 = _strlen((char *)param_2);
    puVar4 = (uint *)_malloc(sVar3 + 3);
    if (puVar4 != (uint *)0x0) {
      FUN_014028f0(puVar4,(uint *)&DAT_0140f354);
      FUN_01402900(puVar4,param_2);
      puVar1 = (uint *)((int)puVar4 + 2);
      goto LAB_014079f4;
    }
LAB_01407a4d:
    local_c = (char *)0xffffffff;
  }
  else {
    if ((puVar1 == (uint *)0x0) || (puVar1 < puVar2)) {
      puVar1 = puVar2;
    }
LAB_014079f4:
    local_c = (char *)0xffffffff;
    pbVar5 = FUN_014076a2((byte *)puVar1,0x2e);
    if (pbVar5 == (byte *)0x0) {
      sVar3 = _strlen((char *)puVar4);
      puVar1 = (uint *)_malloc(sVar3 + 5);
      if (puVar1 == (uint *)0x0) goto LAB_01407a4d;
      FUN_014028f0(puVar1,puVar4);
      sVar3 = _strlen((char *)puVar4);
      ppuVar7 = &PTR_DAT_01413dec;
      do {
        FUN_014028f0((uint *)(sVar3 + (int)puVar1),(uint *)*ppuVar7);
        iVar6 = FUN_0140aa6a((LPCSTR)puVar1,0);
        if (iVar6 != -1) {
          local_c = FUN_01407ac8(param_1,(LPCSTR)puVar1,param_3,param_4);
          break;
        }
        ppuVar7 = (undefined **)((uint **)ppuVar7 + -1);
      } while (0x1413ddf < (int)ppuVar7);
      FUN_01404c4e((undefined *)puVar1);
    }
    else {
      iVar6 = FUN_0140aa6a((LPCSTR)puVar4,0);
      if (iVar6 != -1) {
        local_c = FUN_01407ac8(param_1,(LPCSTR)puVar4,param_3,param_4);
      }
    }
    if (puVar4 != param_2) {
      FUN_01404c4e((undefined *)puVar4);
    }
  }
  return local_c;
}



char * __cdecl FUN_01407ac8(int param_1,LPCSTR param_2,uint **param_3,uint **param_4)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = FUN_0140ad30(param_3,param_4,(uint **)&param_4,(uint **)&param_3);
  if (iVar1 == -1) {
    return (char *)0xffffffff;
  }
  pcVar2 = FUN_0140ab47(param_1,param_2,(char *)param_4,param_3);
  FUN_01404c4e((undefined *)param_4);
  FUN_01404c4e((undefined *)param_3);
  return pcVar2;
}



uint __cdecl FUN_01407b19(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined uVar5;
  undefined2 local_8;
  
  uVar4 = param_1;
  if (param_1 < 0x100) {
    if (((&DAT_01415da1)[param_1] & 0x20) == 0x20) {
      uVar4 = (uint)(byte)(&DAT_01415ca0)[param_1];
    }
  }
  else {
    uVar5 = (undefined)param_1;
    uVar2 = param_1 >> 8;
    uVar1 = param_1 >> 8;
    param_1 = CONCAT13(uVar5,CONCAT12((char)uVar1,(undefined2)param_1));
    if ((((&DAT_01415da1)[uVar2 & 0xff] & 4) != 0) &&
       (iVar3 = FUN_0140a46c(DAT_01415ea4,0x200,(char *)((int)&param_1 + 2),2,&local_8,2,
                             DAT_01415c78,1), iVar3 != 0)) {
      uVar4 = (uint)CONCAT11((undefined)local_8,local_8._1_1_);
    }
  }
  return uVar4;
}



LONG __cdecl FUN_01407b94(int param_1,_EXCEPTION_POINTERS *param_2)

{
  code *pcVar1;
  DWORD DVar2;
  DWORD DVar3;
  DWORD *pDVar4;
  int *piVar5;
  LONG LVar6;
  int iVar7;
  int iVar8;
  
  pDVar4 = FUN_01408431();
  piVar5 = FUN_01407cd2(param_1,(int *)pDVar4[0x14]);
  if ((piVar5 == (int *)0x0) || (pcVar1 = (code *)piVar5[2], pcVar1 == (code *)0x0)) {
    LVar6 = UnhandledExceptionFilter(param_2);
  }
  else if (pcVar1 == (code *)0x5) {
    piVar5[2] = 0;
    LVar6 = 1;
  }
  else {
    if (pcVar1 != (code *)0x1) {
      DVar2 = pDVar4[0x15];
      pDVar4[0x15] = (DWORD)param_2;
      if (piVar5[1] == 8) {
        if (DAT_01413e68 < DAT_01413e6c + DAT_01413e68) {
          iVar7 = DAT_01413e68 * 0xc;
          iVar8 = DAT_01413e68;
          do {
            *(undefined4 *)(iVar7 + 8 + pDVar4[0x14]) = 0;
            iVar8 = iVar8 + 1;
            iVar7 = iVar7 + 0xc;
          } while (iVar8 < DAT_01413e6c + DAT_01413e68);
        }
        iVar7 = *piVar5;
        DVar3 = pDVar4[0x16];
        if (iVar7 == -0x3fffff72) {
          pDVar4[0x16] = 0x83;
        }
        else if (iVar7 == -0x3fffff70) {
          pDVar4[0x16] = 0x81;
        }
        else if (iVar7 == -0x3fffff6f) {
          pDVar4[0x16] = 0x84;
        }
        else if (iVar7 == -0x3fffff6d) {
          pDVar4[0x16] = 0x85;
        }
        else if (iVar7 == -0x3fffff73) {
          pDVar4[0x16] = 0x82;
        }
        else if (iVar7 == -0x3fffff71) {
          pDVar4[0x16] = 0x86;
        }
        else if (iVar7 == -0x3fffff6e) {
          pDVar4[0x16] = 0x8a;
        }
        (*pcVar1)(8,pDVar4[0x16]);
        pDVar4[0x16] = DVar3;
      }
      else {
        piVar5[2] = 0;
        (*pcVar1)(piVar5[1]);
      }
      pDVar4[0x15] = DVar2;
    }
    LVar6 = -1;
  }
  return LVar6;
}



int * __cdecl FUN_01407cd2(int param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = param_2;
  if (*param_2 != param_1) {
    do {
      piVar1 = piVar1 + 3;
      if (param_2 + DAT_01413e74 * 3 <= piVar1) break;
    } while (*piVar1 != param_1);
  }
  if ((param_2 + DAT_01413e74 * 3 <= piVar1) || (*piVar1 != param_1)) {
    piVar1 = (int *)0x0;
  }
  return piVar1;
}



byte * FUN_01407d0c(void)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  
  if (DAT_01416fe8 == 0) {
    FUN_0140a450();
  }
  bVar1 = *DAT_01416ff8;
  pbVar4 = DAT_01416ff8;
  if (bVar1 == 0x22) {
    while( true ) {
      pbVar3 = pbVar4;
      bVar1 = pbVar3[1];
      pbVar4 = pbVar3 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      iVar2 = FUN_0140afca(bVar1);
      if (iVar2 != 0) {
        pbVar4 = pbVar3 + 2;
      }
    }
    if (*pbVar4 == 0x22) goto LAB_01407d49;
  }
  else {
    while (0x20 < bVar1) {
      bVar1 = pbVar4[1];
      pbVar4 = pbVar4 + 1;
    }
  }
  for (; (*pbVar4 != 0 && (*pbVar4 < 0x21)); pbVar4 = pbVar4 + 1) {
LAB_01407d49:
  }
  return pbVar4;
}



void FUN_01407d64(void)

{
  char cVar1;
  size_t sVar2;
  uint **ppuVar3;
  uint *puVar4;
  int iVar5;
  uint *puVar6;
  
  if (DAT_01416fe8 == 0) {
    FUN_0140a450();
  }
  iVar5 = 0;
  for (puVar6 = DAT_01415910; *(char *)puVar6 != '\0'; puVar6 = (uint *)((int)puVar6 + sVar2 + 1)) {
    if (*(char *)puVar6 != '=') {
      iVar5 = iVar5 + 1;
    }
    sVar2 = _strlen((char *)puVar6);
  }
  ppuVar3 = (uint **)_malloc(iVar5 * 4 + 4);
  DAT_0141593c = ppuVar3;
  if (ppuVar3 == (uint **)0x0) {
    __amsg_exit(9);
  }
  cVar1 = *(char *)DAT_01415910;
  puVar6 = DAT_01415910;
  while (cVar1 != '\0') {
    sVar2 = _strlen((char *)puVar6);
    if (*(char *)puVar6 != '=') {
      puVar4 = (uint *)_malloc(sVar2 + 1);
      *ppuVar3 = puVar4;
      if (puVar4 == (uint *)0x0) {
        __amsg_exit(9);
      }
      FUN_014028f0(*ppuVar3,puVar6);
      ppuVar3 = ppuVar3 + 1;
    }
    puVar6 = (uint *)((int)puVar6 + sVar2 + 1);
    cVar1 = *(char *)puVar6;
  }
  FUN_01404c4e((undefined *)DAT_01415910);
  DAT_01415910 = (uint *)0x0;
  *ppuVar3 = (uint *)0x0;
  DAT_01416fe4 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_01407e1d(void)

{
  byte **ppbVar1;
  byte *pbVar2;
  int local_c;
  int local_8;
  
  if (DAT_01416fe8 == 0) {
    FUN_0140a450();
  }
  GetModuleFileNameA((HMODULE)0x0,&DAT_014159d4,0x104);
  _DAT_0141594c = &DAT_014159d4;
  pbVar2 = &DAT_014159d4;
  if (*DAT_01416ff8 != 0) {
    pbVar2 = DAT_01416ff8;
  }
  FUN_01407eb6(pbVar2,(byte **)0x0,(byte *)0x0,&local_8,&local_c);
  ppbVar1 = (byte **)_malloc(local_c + local_8 * 4);
  if (ppbVar1 == (byte **)0x0) {
    __amsg_exit(8);
  }
  FUN_01407eb6(pbVar2,ppbVar1,(byte *)(ppbVar1 + local_8),&local_8,&local_c);
  _DAT_01415934 = ppbVar1;
  _DAT_01415930 = local_8 + -1;
  return;
}



void __cdecl FUN_01407eb6(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  byte *pbVar4;
  byte *pbVar5;
  uint uVar6;
  byte **ppbVar7;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    while( true ) {
      bVar1 = param_1[1];
      pbVar4 = param_1 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      if ((((&DAT_01415da1)[bVar1] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
      {
        *param_3 = *pbVar4;
        param_3 = param_3 + 1;
        pbVar4 = param_1 + 2;
      }
      *param_5 = *param_5 + 1;
      param_1 = pbVar4;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar4;
        param_3 = param_3 + 1;
      }
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar4 == 0x22) {
      pbVar4 = param_1 + 2;
    }
  }
  else {
    do {
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar1 = *param_1;
      pbVar4 = param_1 + 1;
      if (((&DAT_01415da1)[bVar1] & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        pbVar4 = param_1 + 2;
      }
      if (bVar1 == 0x20) break;
      if (bVar1 == 0) goto LAB_01407f61;
      param_1 = pbVar4;
    } while (bVar1 != 9);
    if (bVar1 == 0) {
LAB_01407f61:
      pbVar4 = pbVar4 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar2 = false;
  ppbVar7 = param_2;
  while (*pbVar4 != 0) {
    for (; (*pbVar4 == 0x20 || (*pbVar4 == 9)); pbVar4 = pbVar4 + 1) {
    }
    if (*pbVar4 == 0) break;
    if (ppbVar7 != (byte **)0x0) {
      *ppbVar7 = param_3;
      ppbVar7 = ppbVar7 + 1;
      param_2 = ppbVar7;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar3 = true;
      uVar6 = 0;
      for (; *pbVar4 == 0x5c; pbVar4 = pbVar4 + 1) {
        uVar6 = uVar6 + 1;
      }
      if (*pbVar4 == 0x22) {
        pbVar5 = pbVar4;
        if ((uVar6 & 1) == 0) {
          if ((!bVar2) || (pbVar5 = pbVar4 + 1, pbVar4[1] != 0x22)) {
            bVar3 = false;
            pbVar5 = pbVar4;
          }
          bVar2 = !bVar2;
          ppbVar7 = param_2;
        }
        uVar6 = uVar6 >> 1;
        pbVar4 = pbVar5;
      }
      for (; uVar6 != 0; uVar6 = uVar6 - 1) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      bVar1 = *pbVar4;
      if ((bVar1 == 0) || ((!bVar2 && ((bVar1 == 0x20 || (bVar1 == 9)))))) break;
      if (bVar3) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_01415da1)[bVar1] & 4) != 0) {
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if (((&DAT_01415da1)[bVar1] & 4) != 0) {
            *param_3 = bVar1;
            param_3 = param_3 + 1;
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      pbVar4 = pbVar4 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (ppbVar7 != (byte **)0x0) {
    *ppbVar7 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



undefined4 * FUN_0140806a(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  WCHAR *pWVar4;
  int iVar5;
  size_t mem_Size;
  undefined4 *puVar6;
  char *mem_Size_00;
  LPWCH lpWideCharStr;
  undefined4 *puVar8;
  undefined4 *local_8;
  undefined4 *puVar7;
  
  lpWideCharStr = (LPWCH)0x0;
  puVar8 = (undefined4 *)0x0;
  if (DAT_01415ad8 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr != (LPWCH)0x0) {
      DAT_01415ad8 = 1;
LAB_014080c1:
      if ((lpWideCharStr == (LPWCH)0x0) &&
         (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr == (LPWCH)0x0)) {
        return (undefined4 *)0x0;
      }
      WVar2 = *lpWideCharStr;
      pWVar4 = lpWideCharStr;
      while (WVar2 != L'\0') {
        do {
          pWVar3 = pWVar4;
          pWVar4 = pWVar3 + 1;
        } while (*pWVar4 != L'\0');
        pWVar4 = pWVar3 + 2;
        WVar2 = *pWVar4;
      }
      iVar5 = ((int)pWVar4 - (int)lpWideCharStr >> 1) + 1;
      mem_Size = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
      local_8 = (undefined4 *)0x0;
      if (((mem_Size != 0) &&
          (puVar8 = (undefined4 *)_malloc(mem_Size), puVar8 != (undefined4 *)0x0)) &&
         (iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar8,mem_Size,(LPCSTR)0x0,
                                      (LPBOOL)0x0), local_8 = puVar8, iVar5 == 0)) {
        FUN_01404c4e((undefined *)puVar8);
        local_8 = (undefined4 *)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return local_8;
    }
    puVar8 = (undefined4 *)GetEnvironmentStrings();
    if (puVar8 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_01415ad8 = 2;
  }
  else {
    if (DAT_01415ad8 == 1) goto LAB_014080c1;
    if (DAT_01415ad8 != 2) {
      return (undefined4 *)0x0;
    }
  }
  if ((puVar8 == (undefined4 *)0x0) &&
     (puVar8 = (undefined4 *)GetEnvironmentStrings(), puVar8 == (undefined4 *)0x0)) {
    return (undefined4 *)0x0;
  }
  cVar1 = *(char *)puVar8;
  puVar6 = puVar8;
  while (cVar1 != '\0') {
    do {
      puVar7 = puVar6;
      puVar6 = (undefined4 *)((int)puVar7 + 1);
    } while (*(char *)puVar6 != '\0');
    puVar6 = (undefined4 *)((int)puVar7 + 2);
    cVar1 = *(char *)puVar6;
  }
  mem_Size_00 = (char *)((int)puVar6 + (1 - (int)puVar8));
  puVar6 = (undefined4 *)_malloc((size_t)mem_Size_00);
  if (puVar6 == (undefined4 *)0x0) {
    puVar6 = (undefined4 *)0x0;
  }
  else {
    FUN_01402ad0(puVar6,puVar8,(uint)mem_Size_00);
  }
  FreeEnvironmentStringsA((LPCH)puVar8);
  return puVar6;
}



void FUN_0140819c(void)

{
  HANDLE *ppvVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  DWORD DVar5;
  HANDLE hFile;
  UINT *pUVar6;
  int iVar7;
  uint uVar8;
  UINT UVar9;
  UINT UVar10;
  _STARTUPINFOA local_4c;
  HANDLE *local_8;
  
  puVar3 = (undefined4 *)_malloc(0x480);
  if (puVar3 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_01415fc0 = 0x20;
  DAT_01415ec0 = puVar3;
  for (; puVar3 < DAT_01415ec0 + 0x120; puVar3 = puVar3 + 9) {
    *(undefined *)(puVar3 + 1) = 0;
    *puVar3 = 0xffffffff;
    puVar3[2] = 0;
    *(undefined *)((int)puVar3 + 5) = 10;
  }
  GetStartupInfoA(&local_4c);
  if ((local_4c.cbReserved2 != 0) && ((UINT *)local_4c.lpReserved2 != (UINT *)0x0)) {
    UVar9 = *(UINT *)local_4c.lpReserved2;
    pUVar6 = (UINT *)((int)local_4c.lpReserved2 + 4);
    local_8 = (HANDLE *)((int)pUVar6 + UVar9);
    if (0x7ff < (int)UVar9) {
      UVar9 = 0x800;
    }
    UVar10 = UVar9;
    if ((int)DAT_01415fc0 < (int)UVar9) {
      puVar3 = &DAT_01415ec4;
      do {
        puVar4 = (undefined4 *)_malloc(0x480);
        UVar10 = DAT_01415fc0;
        if (puVar4 == (undefined4 *)0x0) break;
        DAT_01415fc0 = DAT_01415fc0 + 0x20;
        *puVar3 = puVar4;
        puVar2 = puVar4;
        for (; puVar4 < puVar2 + 0x120; puVar4 = puVar4 + 9) {
          *(undefined *)(puVar4 + 1) = 0;
          *puVar4 = 0xffffffff;
          puVar4[2] = 0;
          *(undefined *)((int)puVar4 + 5) = 10;
          puVar2 = (undefined4 *)*puVar3;
        }
        puVar3 = puVar3 + 1;
        UVar10 = UVar9;
      } while ((int)DAT_01415fc0 < (int)UVar9);
    }
    uVar8 = 0;
    if (0 < (int)UVar10) {
      do {
        if (((*local_8 != (HANDLE)0xffffffff) && ((*(byte *)pUVar6 & 1) != 0)) &&
           (((*(byte *)pUVar6 & 8) != 0 || (DVar5 = GetFileType(*local_8), DVar5 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_01415ec0)[(int)uVar8 >> 5] + (uVar8 & 0x1f) * 0x24);
          *ppvVar1 = *local_8;
          *(byte *)(ppvVar1 + 1) = *(byte *)pUVar6;
        }
        local_8 = local_8 + 1;
        uVar8 = uVar8 + 1;
        pUVar6 = (UINT *)((int)pUVar6 + 1);
      } while ((int)uVar8 < (int)UVar10);
    }
  }
  iVar7 = 0;
  do {
    ppvVar1 = (HANDLE *)(DAT_01415ec0 + iVar7 * 9);
    if (DAT_01415ec0[iVar7 * 9] == -1) {
      *(undefined *)(ppvVar1 + 1) = 0x81;
      if (iVar7 == 0) {
        DVar5 = 0xfffffff6;
      }
      else {
        DVar5 = 0xfffffff5 - (iVar7 != 1);
      }
      hFile = GetStdHandle(DVar5);
      if ((hFile != (HANDLE)0xffffffff) && (DVar5 = GetFileType(hFile), DVar5 != 0)) {
        *ppvVar1 = hFile;
        if ((DVar5 & 0xff) != 2) {
          if ((DVar5 & 0xff) == 3) {
            *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 8;
          }
          goto LAB_01408341;
        }
      }
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x40;
    }
    else {
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x80;
    }
LAB_01408341:
    iVar7 = iVar7 + 1;
    if (2 < iVar7) {
      SetHandleCount(DAT_01415fc0);
      return;
    }
  } while( true );
}



void FUN_01408358(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  uint *puVar1;
  uint uVar2;
  
  puVar1 = &DAT_01415ec0;
  do {
    uVar2 = *puVar1;
    if (uVar2 != 0) {
      if (uVar2 < uVar2 + 0x480) {
        lpCriticalSection = (LPCRITICAL_SECTION)(uVar2 + 0xc);
        do {
          if (lpCriticalSection[-1].SpinCount != 0) {
            DeleteCriticalSection(lpCriticalSection);
          }
          uVar2 = uVar2 + 0x24;
          lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[1].OwningThread;
        } while (uVar2 < *puVar1 + 0x480);
      }
      FUN_01404c4e((undefined *)*puVar1);
      *puVar1 = 0;
    }
    puVar1 = puVar1 + 1;
  } while ((int)puVar1 < 0x1415fc0);
  return;
}



undefined4 TLS_Thread_Local_Storage(void)

{
  DWORD *pThreadLocalStorage;
  BOOL bTlsSetValueResult;
  DWORD CurrentThreadID;
  
  Initialize_Thread_Local_Storage();
  g_dwTlsIndex = TlsAlloc();
  if (g_dwTlsIndex != 0xffffffff) {
    pThreadLocalStorage = (DWORD *)Allocate_Memory(1,0x74);
    if (pThreadLocalStorage != (DWORD *)0x0) {
      bTlsSetValueResult = TlsSetValue(g_dwTlsIndex,pThreadLocalStorage);
      if (bTlsSetValueResult != 0) {
        Mem_magic((int)pThreadLocalStorage);
        CurrentThreadID = GetCurrentThreadId();
        pThreadLocalStorage[1] = 0xffffffff;
        *pThreadLocalStorage = CurrentThreadID;
        return 1;
      }
    }
  }
  return 0;
}



void __cdecl Mem_magic(int mem_input)

{
  *(undefined **)(mem_input + 0x50) = &DAT_01413df0;
  *(undefined4 *)(mem_input + 0x14) = 1;
  return;
}



DWORD * FUN_01408431(void)

{
  DWORD dwErrCode;
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  lpTlsValue = (DWORD *)TlsGetValue(g_dwTlsIndex);
  if (lpTlsValue == (DWORD *)0x0) {
    lpTlsValue = (DWORD *)Allocate_Memory(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(g_dwTlsIndex,lpTlsValue);
      if (BVar1 != 0) {
        Mem_magic((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        lpTlsValue[1] = 0xffffffff;
        *lpTlsValue = DVar2;
        goto LAB_0140848c;
      }
    }
    __amsg_exit(0x10);
  }
LAB_0140848c:
  SetLastError(dwErrCode);
  return lpTlsValue;
}



void performExitRoutine(void)

{
  if ((exitFlag == 1) || ((exitFlag == 0 && (exitCondition == 1)))) {
    executeExitProcedure(0xfc);
    if (exitProcedurePointer != (code *)0x0) {
      (*exitProcedurePointer)();
    }
    executeExitProcedure(0xff);
  }
  return;
}



void __cdecl executeExitProcedure(DWORD input_param)

{
  DWORD *pDVar2;
  DWORD DVar3;
  size_t sVar4;
  HANDLE StdHandel;
  int iVar5;
  uint *_Dest;
  undefined auStackY_1e3 [7];
  uint local_1a8 [65];
  uint local_a4 [40];
  char *lpBuffer;
  LPOVERLAPPED lpOverlapped;
  char **ppcVar1;
  
  iVar5 = 0;
  pDVar2 = &DAT_01413ea0_value2;
  do {
    if (input_param == *pDVar2) break;
    pDVar2 = pDVar2 + 2;
    iVar5 = iVar5 + 1;
  } while ((int)pDVar2 < 0x1413f30);
  if (input_param == (&DAT_01413ea0_value2)[iVar5 * 2]) {
    if ((exitFlag == 1) || ((exitFlag == 0 && (exitCondition == 1)))) {
      pDVar2 = &input_param;
      ppcVar1 = (char **)(iVar5 * 8 + 0x1413ea4);
      lpOverlapped = (LPOVERLAPPED)0x0;
      sVar4 = _strlen(*ppcVar1);
      lpBuffer = *ppcVar1;
      StdHandel = GetStdHandle(0xfffffff4);
      WriteFile(StdHandel,lpBuffer,sVar4,pDVar2,lpOverlapped);
    }
    else if (input_param != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_1a8,0x104);
      if (DVar3 == 0) {
        FUN_014028f0(local_1a8,(uint *)"<program name unknown>");
      }
      _Dest = local_1a8;
      sVar4 = _strlen((char *)local_1a8);
      if (0x3c < sVar4 + 1) {
        sVar4 = _strlen((char *)local_1a8);
        _Dest = (uint *)(auStackY_1e3 + sVar4);
        _strncpy((char *)_Dest,"...",3);
      }
      FUN_014028f0(local_a4,(uint *)"Runtime Error!\n\nProgram: ");
      FUN_01402900(local_a4,_Dest);
      FUN_01402900(local_a4,(uint *)&DAT_0140f60c);
      FUN_01402900(local_a4,*(uint **)(iVar5 * 8 + 0x1413ea4));
      auStackY_1e3._3_4_ = 0x14086a1;
      Window_MessageBox_Manager(local_a4,"Microsoft Visual C++ Runtime Library",0x12010);
    }
  }
  return;
}



BOOL __cdecl
FUN_01408701(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
            int param_7)

{
  undefined *puVar1;
  BOOL BVar2;
  int iVar3;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  WORD local_20 [2];
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f650;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffc8;
  iVar3 = DAT_01415ae0;
  puVar1 = &stack0xffffffc8;
  if (DAT_01415ae0 == 0) {
    BVar2 = GetStringTypeW(1,L"",1,local_20);
    iVar3 = 1;
    puVar1 = local_1c;
    if (BVar2 != 0) goto LAB_01408770;
    BVar2 = GetStringTypeA(0,1,"",1,local_20);
    if (BVar2 != 0) {
      iVar3 = 2;
      puVar1 = local_1c;
      goto LAB_01408770;
    }
  }
  else {
LAB_01408770:
    local_1c = puVar1;
    DAT_01415ae0 = iVar3;
    if (DAT_01415ae0 == 2) {
      if (param_6 == 0) {
        param_6 = DAT_01415bc0;
      }
      BVar2 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
      goto LAB_01408838;
    }
    if (DAT_01415ae0 == 1) {
      if (param_5 == 0) {
        param_5 = DAT_01415bd0;
      }
      iVar3 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,
                                  (LPWSTR)0x0,0);
      if (iVar3 != 0) {
        local_8 = 0;
        FUN_014028c0(unaff_DI);
        local_1c = &stack0xffffffc8;
        Initialize_Memory(&stack0xffffffc8,0,iVar3 * 2);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x38) &&
           (iVar3 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)&stack0xffffffc8,iVar3),
           iVar3 != 0)) {
          BVar2 = GetStringTypeW(param_1,(LPCWSTR)&stack0xffffffc8,iVar3,param_4);
          goto LAB_01408838;
        }
      }
    }
  }
  BVar2 = 0;
LAB_01408838:
  *unaff_FS_OFFSET = local_14;
  return BVar2;
}



int * __cdecl Allocate_Memory(int iNumElements,int iElementSize)

{
  int iVar1;
  uint *pRequestedSize;
  uint *puAdjustedSize;
  undefined4 *unaff_FS_OFFSET;
  uint *_Size;
  int *pAllocatedMemory;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f660;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  pRequestedSize = (uint *)(iNumElements * iElementSize);
  puAdjustedSize = pRequestedSize;
  if (pRequestedSize < (uint *)0xffffffe1) {
    if (pRequestedSize == (uint *)0x0) {
      puAdjustedSize = (uint *)0x1;
    }
    puAdjustedSize = (uint *)((int)puAdjustedSize + 0xfU & 0xfffffff0);
  }
  do {
    pAllocatedMemory = (int *)0x0;
    if (puAdjustedSize < (uint *)0xffffffe1) {
      if (DAT_01415fc8 == 3) {
        if (pRequestedSize <= DAT_01417018) {
          critical_code_area_executor(9);
          local_8 = 0;
          pAllocatedMemory = Allocate_Memory(pRequestedSize);
          local_8 = 0xffffffff;
          endCritical_9();
          _Size = pRequestedSize;
          if (pAllocatedMemory == (int *)0x0) goto LAB_01408937;
LAB_01408926:
          Initialize_Memory(pAllocatedMemory,0,(size_t)_Size);
        }
LAB_01408932:
        if (pAllocatedMemory != (int *)0x0) goto LAB_01408978;
      }
      else {
        if ((DAT_01415fc8 != 2) || (DAT_014136e4 < puAdjustedSize)) goto LAB_01408932;
        critical_code_area_executor(9);
        local_8 = 1;
        pAllocatedMemory = Memory_manager((int *)((uint)puAdjustedSize >> 4));
        local_8 = 0xffffffff;
        endCritical_9();
        _Size = puAdjustedSize;
        if (pAllocatedMemory != (int *)0x0) goto LAB_01408926;
      }
LAB_01408937:
      pAllocatedMemory = (int *)HeapAlloc(DAT_01415fc4,8,(SIZE_T)puAdjustedSize);
    }
    if ((pAllocatedMemory != (int *)0x0) || (DAT_014159cc == 0)) goto LAB_01408978;
    iVar1 = CheckMemoryAllocation((int)puAdjustedSize);
  } while (iVar1 != 0);
  pAllocatedMemory = (int *)0x0;
LAB_01408978:
  *unaff_FS_OFFSET = local_14;
  return pAllocatedMemory;
}



void endCritical_9(void)

{
  endCriticalFromID(9);
  return;
}



void endCritical_9(void)

{
  endCriticalFromID(9);
  return;
}



uint FUN_01408a08(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int *piVar3;
  uint uVar4;
  int local_8;
  int local_4;
  
  uVar4 = 0xffffffff;
  critical_code_area_executor(0x12);
  local_8 = 0;
  local_4 = 0;
  piVar3 = &DAT_01415ec0;
  while (puVar2 = (undefined4 *)*piVar3, puVar1 = puVar2, puVar2 != (undefined4 *)0x0) {
    for (; puVar2 < puVar1 + 0x120; puVar2 = puVar2 + 9) {
      if ((*(byte *)(puVar2 + 1) & 1) == 0) {
        if (puVar2[2] == 0) {
          critical_code_area_executor(0x11);
          if (puVar2[2] == 0) {
            InitializeCriticalSection((LPCRITICAL_SECTION)(puVar2 + 3));
            puVar2[2] = puVar2[2] + 1;
          }
          endCriticalFromID(0x11);
        }
        EnterCriticalSection((LPCRITICAL_SECTION)(puVar2 + 3));
        if ((*(byte *)(puVar2 + 1) & 1) == 0) {
          *puVar2 = 0xffffffff;
          uVar4 = ((int)puVar2 - *piVar3) / 0x24 + local_4;
          if (uVar4 != 0xffffffff) goto LAB_01408b1a;
          break;
        }
        LeaveCriticalSection((LPCRITICAL_SECTION)(puVar2 + 3));
      }
      puVar1 = (undefined4 *)*piVar3;
    }
    local_4 = local_4 + 0x20;
    piVar3 = piVar3 + 1;
    local_8 = local_8 + 1;
    if (0x1415fbf < (int)piVar3) goto LAB_01408b1a;
  }
  puVar2 = (undefined4 *)_malloc(0x480);
  if (puVar2 != (undefined4 *)0x0) {
    DAT_01415fc0 = DAT_01415fc0 + 0x20;
    (&DAT_01415ec0)[local_8] = puVar2;
    puVar1 = puVar2;
    for (; puVar2 < puVar1 + 0x120; puVar2 = puVar2 + 9) {
      *(undefined *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      puVar2[2] = 0;
      *(undefined *)((int)puVar2 + 5) = 10;
      puVar1 = (undefined4 *)(&DAT_01415ec0)[local_8];
    }
    uVar4 = local_8 << 5;
    FUN_01408d0f(uVar4);
  }
LAB_01408b1a:
  endCriticalFromID(0x12);
  return uVar4;
}



undefined4 __cdecl FUN_01408b2b(uint param_1,HANDLE param_2)

{
  DWORD *pDVar1;
  int iVar2;
  DWORD nStdHandle;
  
  if (param_1 < DAT_01415fc0) {
    iVar2 = (param_1 & 0x1f) * 0x24;
    if (*(int *)((&DAT_01415ec0)[(int)param_1 >> 5] + iVar2) == -1) {
      if (exitCondition == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_01408b84;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,param_2);
      }
LAB_01408b84:
      *(HANDLE *)((&DAT_01415ec0)[(int)param_1 >> 5] + iVar2) = param_2;
      return 0;
    }
  }
  pDVar1 = FUN_01406c66();
  *pDVar1 = 9;
  pDVar1 = FUN_01406c6f();
  *pDVar1 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_01408ba7(uint param_1)

{
  int *piVar1;
  DWORD *pDVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if (param_1 < DAT_01415fc0) {
    iVar3 = (param_1 & 0x1f) * 0x24;
    piVar1 = (int *)((&DAT_01415ec0)[(int)param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (exitCondition == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_01408c03;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_01408c03:
      *(undefined4 *)((&DAT_01415ec0)[(int)param_1 >> 5] + iVar3) = 0xffffffff;
      return 0;
    }
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  pDVar2 = FUN_01406c6f();
  *pDVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_01408c26(uint param_1)

{
  DWORD *pDVar1;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    return *(undefined4 *)((&DAT_01415ec0)[(int)param_1 >> 5] + (param_1 & 0x1f) * 0x24);
  }
  pDVar1 = FUN_01406c66();
  *pDVar1 = 9;
  pDVar1 = FUN_01406c6f();
  *pDVar1 = 0;
  return 0xffffffff;
}



uint __cdecl FUN_01408c68(HANDLE param_1,uint param_2)

{
  DWORD DVar1;
  uint uVar2;
  DWORD *pDVar3;
  byte bVar4;
  
  bVar4 = 0;
  if ((param_2 & 8) != 0) {
    bVar4 = 0x20;
  }
  if ((param_2 & 0x4000) != 0) {
    bVar4 = bVar4 | 0x80;
  }
  if ((param_2 & 0x80) != 0) {
    bVar4 = bVar4 | 0x10;
  }
  DVar1 = GetFileType(param_1);
  if (DVar1 == 0) {
    DVar1 = GetLastError();
    FUN_01406bf3(DVar1);
  }
  else {
    if (DVar1 == 2) {
      bVar4 = bVar4 | 0x40;
    }
    else if (DVar1 == 3) {
      bVar4 = bVar4 | 8;
    }
    uVar2 = FUN_01408a08();
    if (uVar2 != 0xffffffff) {
      FUN_01408b2b(uVar2,param_1);
      *(byte *)((&DAT_01415ec0)[(int)uVar2 >> 5] + 4 + (uVar2 & 0x1f) * 0x24) = bVar4 | 1;
      FUN_01408d6e(uVar2);
      return uVar2;
    }
    pDVar3 = FUN_01406c66();
    *pDVar3 = 0x18;
    pDVar3 = FUN_01406c6f();
    *pDVar3 = 0;
  }
  return 0xffffffff;
}



void __cdecl FUN_01408d0f(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (param_1 & 0x1f) * 0x24;
  iVar1 = (&DAT_01415ec0)[(int)param_1 >> 5] + iVar2;
  if (*(int *)(iVar1 + 8) == 0) {
    critical_code_area_executor(0x11);
    if (*(int *)(iVar1 + 8) == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)(iVar1 + 0xc));
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
    }
    endCriticalFromID(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((&DAT_01415ec0)[(int)param_1 >> 5] + 0xc + iVar2));
  return;
}



void __cdecl FUN_01408d6e(uint param_1)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_01415ec0)[(int)param_1 >> 5] + 0xc + (param_1 & 0x1f) * 0x24));
  return;
}



DWORD __cdecl FUN_01408d90(uint param_1)

{
  HANDLE hFile;
  BOOL BVar1;
  DWORD DVar2;
  DWORD *pDVar3;
  int iVar4;
  
  if (DAT_01415fc0 <= param_1) {
LAB_01408e11:
    pDVar3 = FUN_01406c66();
    *pDVar3 = 9;
    return 0xffffffff;
  }
  iVar4 = (param_1 & 0x1f) * 0x24;
  if ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + iVar4) & 1) == 0) goto LAB_01408e11;
  FUN_01408d0f(param_1);
  if ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + iVar4) & 1) != 0) {
    hFile = (HANDLE)FUN_01408c26(param_1);
    BVar1 = FlushFileBuffers(hFile);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
    }
    else {
      DVar2 = 0;
    }
    if (DVar2 == 0) goto LAB_01408e06;
    pDVar3 = FUN_01406c6f();
    *pDVar3 = DVar2;
  }
  pDVar3 = FUN_01406c66();
  *pDVar3 = 9;
  DVar2 = 0xffffffff;
LAB_01408e06:
  FUN_01408d6e(param_1);
  return DVar2;
}



int __cdecl FUN_01408e23(uint param_1,char *param_2,uint param_3)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01408d0f(param_1);
    iVar1 = FUN_01408e88(param_1,param_2,param_3);
    FUN_01408d6e(param_1);
    return iVar1;
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  pDVar2 = FUN_01406c6f();
  *pDVar2 = 0;
  return -1;
}



int __cdecl FUN_01408e88(DWORD param_1,char *param_2,uint param_3)

{
  int *piVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  char *pcVar5;
  BOOL BVar6;
  DWORD *pDVar7;
  char local_418 [1028];
  int local_14;
  DWORD local_10;
  DWORD local_c;
  char *local_8;
  
  local_c = 0;
  local_14 = 0;
  if (param_3 == 0) {
LAB_01408ea1:
    iVar4 = 0;
  }
  else {
    piVar1 = &DAT_01415ec0 + ((int)param_1 >> 5);
    iVar4 = (param_1 & 0x1f) * 0x24;
    if ((*(byte *)(*piVar1 + 4 + iVar4) & 0x20) != 0) {
      FUN_014097b0(param_1,0,2);
    }
    if ((*(byte *)((HANDLE *)(*piVar1 + iVar4) + 1) & 0x80) == 0) {
      BVar6 = WriteFile(*(HANDLE *)(*piVar1 + iVar4),param_2,param_3,&local_10,(LPOVERLAPPED)0x0);
      if (BVar6 == 0) {
        param_1 = GetLastError();
      }
      else {
        local_c = local_10;
        param_1 = 0;
      }
LAB_01408f70:
      if (local_c != 0) {
        return local_c - local_14;
      }
      if (param_1 == 0) goto LAB_01408fe2;
      if (param_1 == 5) {
        pDVar7 = FUN_01406c66();
        *pDVar7 = 9;
        pDVar7 = FUN_01406c6f();
        *pDVar7 = 5;
      }
      else {
        FUN_01406bf3(param_1);
      }
    }
    else {
      local_8 = param_2;
      param_1 = 0;
      if (param_3 != 0) {
        do {
          pcVar5 = local_418;
          do {
            if (param_3 <= (uint)((int)local_8 - (int)param_2)) break;
            pcVar2 = local_8 + 1;
            cVar3 = *local_8;
            local_8 = pcVar2;
            if (cVar3 == '\n') {
              local_14 = local_14 + 1;
              *pcVar5 = '\r';
              pcVar5 = pcVar5 + 1;
            }
            *pcVar5 = cVar3;
            pcVar5 = pcVar5 + 1;
          } while ((int)pcVar5 - (int)local_418 < 0x400);
          BVar6 = WriteFile(*(HANDLE *)(*piVar1 + iVar4),local_418,(int)pcVar5 - (int)local_418,
                            &local_10,(LPOVERLAPPED)0x0);
          if (BVar6 == 0) {
            param_1 = GetLastError();
            goto LAB_01408f70;
          }
          local_c = local_c + local_10;
          if (((int)local_10 < (int)pcVar5 - (int)local_418) ||
             (param_3 <= (uint)((int)local_8 - (int)param_2))) goto LAB_01408f70;
        } while( true );
      }
LAB_01408fe2:
      if (((*(byte *)(*piVar1 + 4 + iVar4) & 0x40) != 0) && (*param_2 == '\x1a')) goto LAB_01408ea1;
      pDVar7 = FUN_01406c66();
      *pDVar7 = 0x1c;
      pDVar7 = FUN_01406c6f();
      *pDVar7 = 0;
    }
    iVar4 = -1;
  }
  return iVar4;
}



int __cdecl FUN_01409013(uint param_1,char *param_2,char *param_3)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01408d0f(param_1);
    iVar1 = FUN_01409078(param_1,param_2,param_3);
    FUN_01408d6e(param_1);
    return iVar1;
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  pDVar2 = FUN_01406c6f();
  *pDVar2 = 0;
  return -1;
}



int __cdecl FUN_01409078(uint param_1,char *param_2,char *param_3)

{
  int *piVar1;
  byte *pbVar2;
  char cVar3;
  byte bVar4;
  BOOL BVar5;
  DWORD DVar6;
  DWORD *pDVar7;
  char *pcVar8;
  int iVar9;
  DWORD local_10;
  char *local_c;
  char local_5;
  
  local_c = (char *)0x0;
  if (param_3 != (char *)0x0) {
    piVar1 = &DAT_01415ec0 + ((int)param_1 >> 5);
    iVar9 = (param_1 & 0x1f) * 0x24;
    bVar4 = *(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + iVar9 + 4);
    if ((bVar4 & 2) == 0) {
      pcVar8 = param_2;
      if (((bVar4 & 0x48) != 0) &&
         (cVar3 = *(char *)((&DAT_01415ec0)[(int)param_1 >> 5] + iVar9 + 5), cVar3 != '\n')) {
        param_3 = param_3 + -1;
        *param_2 = cVar3;
        pcVar8 = param_2 + 1;
        local_c = (char *)0x1;
        *(undefined *)(*piVar1 + 5 + iVar9) = 10;
      }
      BVar5 = ReadFile(*(HANDLE *)(*piVar1 + iVar9),pcVar8,(DWORD)param_3,&local_10,
                       (LPOVERLAPPED)0x0);
      if (BVar5 == 0) {
        DVar6 = GetLastError();
        if (DVar6 == 5) {
          pDVar7 = FUN_01406c66();
          *pDVar7 = 9;
          pDVar7 = FUN_01406c6f();
          *pDVar7 = 5;
        }
        else {
          if (DVar6 == 0x6d) {
            return 0;
          }
          FUN_01406bf3(DVar6);
        }
        return -1;
      }
      bVar4 = *(byte *)(*piVar1 + 4 + iVar9);
      if ((bVar4 & 0x80) == 0) {
        return (int)local_c + local_10;
      }
      if ((local_10 == 0) || (*param_2 != '\n')) {
        bVar4 = bVar4 & 0xfb;
      }
      else {
        bVar4 = bVar4 | 4;
      }
      *(byte *)(*piVar1 + 4 + iVar9) = bVar4;
      param_3 = param_2;
      local_c = param_2 + (int)local_c + local_10;
      pcVar8 = param_2;
      if (param_2 < local_c) {
        do {
          cVar3 = *param_3;
          if (cVar3 == '\x1a') {
            pbVar2 = (byte *)(*piVar1 + 4 + iVar9);
            bVar4 = *pbVar2;
            if ((bVar4 & 0x40) == 0) {
              *pbVar2 = bVar4 | 2;
            }
            break;
          }
          if (cVar3 == '\r') {
            if (param_3 < local_c + -1) {
              if (param_3[1] == '\n') {
                param_3 = param_3 + 2;
                goto LAB_01409203;
              }
              *pcVar8 = '\r';
              pcVar8 = pcVar8 + 1;
              param_3 = param_3 + 1;
            }
            else {
              param_3 = param_3 + 1;
              BVar5 = ReadFile(*(HANDLE *)(*piVar1 + iVar9),&local_5,1,&local_10,(LPOVERLAPPED)0x0);
              if (((BVar5 == 0) && (DVar6 = GetLastError(), DVar6 != 0)) || (local_10 == 0)) {
LAB_0140921d:
                *pcVar8 = '\r';
LAB_01409220:
                pcVar8 = pcVar8 + 1;
              }
              else if ((*(byte *)(*piVar1 + 4 + iVar9) & 0x48) == 0) {
                if ((pcVar8 == param_2) && (local_5 == '\n')) {
LAB_01409203:
                  *pcVar8 = '\n';
                  goto LAB_01409220;
                }
                FUN_014097b0(param_1,-1,1);
                if (local_5 != '\n') goto LAB_0140921d;
              }
              else {
                if (local_5 == '\n') goto LAB_01409203;
                *pcVar8 = '\r';
                pcVar8 = pcVar8 + 1;
                *(char *)(*piVar1 + 5 + iVar9) = local_5;
              }
            }
          }
          else {
            *pcVar8 = cVar3;
            pcVar8 = pcVar8 + 1;
            param_3 = param_3 + 1;
          }
        } while (param_3 < local_c);
      }
      return (int)pcVar8 - (int)param_2;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_01409251(undefined4 *param_1)

{
  void *pvVar1;
  
  _DAT_014159c0 = _DAT_014159c0 + 1;
  pvVar1 = _malloc(0x1000);
  param_1[2] = pvVar1;
  if (pvVar1 == (void *)0x0) {
    param_1[3] = param_1[3] | 4;
    param_1[2] = param_1 + 5;
    param_1[6] = 2;
  }
  else {
    param_1[3] = param_1[3] | 8;
    param_1[6] = 0x1000;
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return;
}



byte __cdecl FUN_01409295(uint param_1)

{
  if (DAT_01415fc0 <= param_1) {
    return 0;
  }
  return *(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 0x40;
}



LPSTR __cdecl FUN_014092be(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  bool bVar2;
  
  InterlockedIncrement(&DAT_01415c74);
  bVar2 = DAT_01415c70 != 0;
  if (bVar2) {
    InterlockedDecrement(&DAT_01415c74);
    critical_code_area_executor(0x13);
  }
  pCVar1 = FUN_01409317(param_1,param_2);
  if (bVar2) {
    endCriticalFromID(0x13);
  }
  else {
    InterlockedDecrement(&DAT_01415c74);
  }
  return pCVar1;
}



LPSTR __cdecl FUN_01409317(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  DWORD *pDVar2;
  
  pCVar1 = param_1;
  if (param_1 == (LPSTR)0x0) {
    return param_1;
  }
  if (DAT_01415bc0 == 0) {
    if ((ushort)param_2 < 0x100) {
      *param_1 = (CHAR)param_2;
      return (LPSTR)0x1;
    }
  }
  else {
    param_1 = (LPSTR)0x0;
    pCVar1 = (LPSTR)WideCharToMultiByte(DAT_01415bd0,0x220,&param_2,1,pCVar1,DAT_014139c4,
                                        (LPCSTR)0x0,(LPBOOL)&param_1);
    if ((pCVar1 != (LPSTR)0x0) && (param_1 == (LPSTR)0x0)) {
      return pCVar1;
    }
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 0x2a;
  return (LPSTR)0xffffffff;
}



// Library Function - Single Match
//  __aulldiv
// 
// Library: Visual Studio

undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __aullrem
// 
// Library: Visual Studio

undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_1;
  uVar4 = param_4;
  uVar9 = param_2;
  uVar10 = param_3;
  if (param_4 == 0) {
    iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_2 < uVar10)) || ((param_2 <= uVar10 && (param_1 < uVar4))))
    {
      bVar11 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar10 = (uVar10 - param_4) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_1);
    iVar7 = -(uint)(uVar4 - param_1 != 0) - ((uVar10 - param_2) - (uint)(uVar4 < param_1));
  }
  return CONCAT44(iVar7,iVar6);
}



uint __cdecl FUN_0140947c(LPCSTR param_1,uint param_2,uint param_3,uint param_4)

{
  byte *pbVar1;
  uint uVar2;
  DWORD *pDVar3;
  HANDLE hFile;
  int iVar4;
  DWORD DVar5;
  int iVar6;
  uint uVar7;
  bool bVar8;
  _SECURITY_ATTRIBUTES local_20;
  DWORD local_14;
  undefined4 local_10;
  DWORD local_c;
  byte local_5;
  
  bVar8 = (param_2 & 0x80) == 0;
  local_20.nLength = 0xc;
  local_20.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar8) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_20.bInheritHandle = (BOOL)bVar8;
  if (((param_2 & 0x8000) == 0) && (((param_2 & 0x4000) != 0 || (DAT_01415be4 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar2 = param_2 & 3;
  if (uVar2 == 0) {
    local_10 = 0x80000000;
  }
  else if (uVar2 == 1) {
    local_10 = 0x40000000;
  }
  else {
    if (uVar2 != 2) goto LAB_01409580;
    local_10 = 0xc0000000;
  }
  if (param_3 == 0x10) {
    local_14 = 0;
  }
  else if (param_3 == 0x20) {
    local_14 = 1;
  }
  else if (param_3 == 0x30) {
    local_14 = 2;
  }
  else {
    if (param_3 != 0x40) goto LAB_01409580;
    local_14 = 3;
  }
  uVar2 = param_2 & 0x700;
  if (uVar2 < 0x401) {
    if ((uVar2 == 0x400) || (uVar2 == 0)) {
      local_c = 3;
    }
    else if (uVar2 == 0x100) {
      local_c = 4;
    }
    else {
      if (uVar2 == 0x200) goto LAB_0140959a;
      if (uVar2 != 0x300) goto LAB_01409580;
      local_c = 2;
    }
  }
  else {
    if (uVar2 != 0x500) {
      if (uVar2 == 0x600) {
LAB_0140959a:
        local_c = 5;
        goto LAB_014095aa;
      }
      if (uVar2 != 0x700) {
LAB_01409580:
        pDVar3 = FUN_01406c66();
        *pDVar3 = 0x16;
        pDVar3 = FUN_01406c6f();
        *pDVar3 = 0;
        return 0xffffffff;
      }
    }
    local_c = 1;
  }
LAB_014095aa:
  DVar5 = 0x80;
  if (((param_2 & 0x100) != 0) && ((~DAT_0141591c & param_4 & 0x80) == 0)) {
    DVar5 = 1;
  }
  if ((param_2 & 0x40) != 0) {
    DVar5 = DVar5 | 0x4000000;
    local_10 = CONCAT13(local_10._3_1_,0x10000);
  }
  if ((param_2 & 0x1000) != 0) {
    DVar5 = DVar5 | 0x100;
  }
  if ((param_2 & 0x20) == 0) {
    if ((param_2 & 0x10) != 0) {
      DVar5 = DVar5 | 0x10000000;
    }
  }
  else {
    DVar5 = DVar5 | 0x8000000;
  }
  uVar2 = FUN_01408a08();
  if (uVar2 == 0xffffffff) {
    pDVar3 = FUN_01406c66();
    *pDVar3 = 0x18;
    pDVar3 = FUN_01406c6f();
    *pDVar3 = 0;
    return 0xffffffff;
  }
  hFile = CreateFileA(param_1,local_10,local_14,&local_20,local_c,DVar5,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    DVar5 = GetFileType(hFile);
    if (DVar5 != 0) {
      if (DVar5 == 2) {
        local_5 = local_5 | 0x40;
      }
      else if (DVar5 == 3) {
        local_5 = local_5 | 8;
      }
      FUN_01408b2b(uVar2,hFile);
      iVar6 = (uVar2 & 0x1f) * 0x24;
      param_1._3_1_ = local_5 & 0x48;
      *(byte *)((&DAT_01415ec0)[(int)uVar2 >> 5] + 4 + iVar6) = local_5 | 1;
      if ((((local_5 & 0x48) == 0) && ((local_5 & 0x80) != 0)) && ((param_2 & 2) != 0)) {
        local_14 = FUN_014097b0(uVar2,-1,2);
        if (local_14 == 0xffffffff) {
          pDVar3 = FUN_01406c6f();
          if (*pDVar3 == 0x83) goto LAB_01409724;
        }
        else {
          param_3 = param_3 & 0xffffff;
          iVar4 = FUN_01409078(uVar2,(char *)((int)&param_3 + 3),(char *)0x1);
          if ((((iVar4 != 0) || (param_3._3_1_ != '\x1a')) ||
              (iVar4 = FUN_0140b7a8(uVar2,local_14), iVar4 != -1)) &&
             (DVar5 = FUN_014097b0(uVar2,0,0), DVar5 != 0xffffffff)) goto LAB_01409724;
        }
        FUN_01405c95(uVar2);
        uVar7 = 0xffffffff;
      }
      else {
LAB_01409724:
        uVar7 = uVar2;
        if ((param_1._3_1_ == 0) && ((param_2 & 8) != 0)) {
          pbVar1 = (byte *)((&DAT_01415ec0)[(int)uVar2 >> 5] + 4 + iVar6);
          *pbVar1 = *pbVar1 | 0x20;
        }
      }
      goto LAB_0140973d;
    }
    CloseHandle(hFile);
  }
  DVar5 = GetLastError();
  FUN_01406bf3(DVar5);
  uVar7 = 0xffffffff;
LAB_0140973d:
  FUN_01408d6e(uVar2);
  return uVar7;
}



DWORD __cdecl FUN_0140974b(uint param_1,LONG param_2,DWORD param_3)

{
  DWORD DVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01408d0f(param_1);
    DVar1 = FUN_014097b0(param_1,param_2,param_3);
    FUN_01408d6e(param_1);
    return DVar1;
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  pDVar2 = FUN_01406c6f();
  *pDVar2 = 0;
  return 0xffffffff;
}



DWORD __cdecl FUN_014097b0(uint param_1,LONG param_2,DWORD param_3)

{
  byte *pbVar1;
  HANDLE hFile;
  DWORD *pDVar2;
  DWORD DVar3;
  uint uVar4;
  
  hFile = (HANDLE)FUN_01408c26(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    pDVar2 = FUN_01406c66();
    *pDVar2 = 9;
  }
  else {
    DVar3 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
    if (DVar3 == 0xffffffff) {
      uVar4 = GetLastError();
    }
    else {
      uVar4 = 0;
    }
    if (uVar4 == 0) {
      pbVar1 = (byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24);
      *pbVar1 = *pbVar1 & 0xfd;
      return DVar3;
    }
    FUN_01406bf3(uVar4);
  }
  return 0xffffffff;
}



void InitializeCriticalSection(void)

{
  if (DAT_01415ba0 == 0) {
    critical_code_area_executor(0xb);
    if (DAT_01415ba0 == 0) {
      InitializeCriticalSectionAndSpinCount();
      DAT_01415ba0 = DAT_01415ba0 + 1;
    }
    endCriticalFromID(0xb);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void InitializeCriticalSectionAndSpinCount(void)

{
  char cVar1;
  char cVar2;
  uint *_Str1;
  DWORD DVar3;
  int iTimeT;
  size_t sVar4;
  void *this;
  uint *_Source;
  int local_8;
  
  critical_code_area_executor(0xc);
  DAT_01413ff8 = 0xffffffff;
  DAT_01413fe8 = 0xffffffff;
  DAT_01415ae8 = 0;
  _Str1 = (uint *)FUN_0140ba3e("TZ");
  if (_Str1 == (uint *)0x0) {
    endCriticalFromID(0xc);
    DVar3 = GetTimeZoneInformation((LPTIME_ZONE_INFORMATION)&DAT_01415af0);
    if (DVar3 == 0xffffffff) {
      return;
    }
    DAT_01413f50 = (void *)(DAT_01415af0 * 0x3c);
    DAT_01415ae8 = 1;
    if (DAT_01415b36 != 0) {
      DAT_01413f50 = (void *)((int)DAT_01413f50 + DAT_01415b44 * 0x3c);
    }
    if ((DAT_01415b8a == 0) || (DAT_01415b98 == 0)) {
      DAT_01413f54 = 0;
      _DAT_01413f58 = 0;
    }
    else {
      DAT_01413f54 = 1;
      _DAT_01413f58 = (DAT_01415b98 - DAT_01415b44) * 0x3c;
    }
    iTimeT = WideCharToMultiByte(DAT_01415bd0,0x220,(LPCWSTR)&DAT_01415af4,-1,PTR_DAT_01413fdc,0x3f,
                                 (LPCSTR)0x0,&local_8);
    if ((iTimeT == 0) || (local_8 != 0)) {
      *PTR_DAT_01413fdc = 0;
    }
    else {
      PTR_DAT_01413fdc[0x3f] = 0;
    }
    iTimeT = WideCharToMultiByte(DAT_01415bd0,0x220,(LPCWSTR)&DAT_01415b48,-1,PTR_DAT_01413fe0,0x3f,
                                 (LPCSTR)0x0,&local_8);
    if ((iTimeT != 0) && (local_8 == 0)) {
      PTR_DAT_01413fe0[0x3f] = 0;
      return;
    }
LAB_01409ad8:
    *PTR_DAT_01413fe0 = 0;
  }
  else {
    if ((*(char *)_Str1 != '\0') &&
       ((DAT_01415b9c == (uint *)0x0 ||
        (iTimeT = _strcmp((char *)_Str1,(char *)DAT_01415b9c), iTimeT != 0)))) {
      FUN_01404c4e((undefined *)DAT_01415b9c);
      sVar4 = _strlen((char *)_Str1);
      DAT_01415b9c = (uint *)_malloc(sVar4 + 1);
      if (DAT_01415b9c != (uint *)0x0) {
        FUN_014028f0(DAT_01415b9c,_Str1);
        endCriticalFromID(0xc);
        _strncpy(PTR_DAT_01413fdc,(char *)_Str1,3);
        _Source = (uint *)((int)_Str1 + 3);
        PTR_DAT_01413fdc[3] = 0;
        cVar2 = *(char *)_Source;
        if (cVar2 == '-') {
          _Source = _Str1 + 1;
        }
        iTimeT = FUN_0140b8cd(this,(byte *)_Source);
        DAT_01413f50 = (void *)(iTimeT * 0xe10);
        for (; (cVar1 = *(char *)_Source, cVar1 == '+' || (('/' < cVar1 && (cVar1 < ':'))));
            _Source = (uint *)((int)_Source + 1)) {
        }
        if (*(char *)_Source == ':') {
          _Source = (uint *)((int)_Source + 1);
          iTimeT = FUN_0140b8cd(DAT_01413f50,(byte *)_Source);
          DAT_01413f50 = (void *)((int)DAT_01413f50 + iTimeT * 0x3c);
          for (; ('/' < *(char *)_Source && (*(char *)_Source < ':'));
              _Source = (uint *)((int)_Source + 1)) {
          }
          if (*(char *)_Source == ':') {
            _Source = (uint *)((int)_Source + 1);
            iTimeT = FUN_0140b8cd(DAT_01413f50,(byte *)_Source);
            DAT_01413f50 = (void *)((int)DAT_01413f50 + iTimeT);
            for (; ('/' < *(char *)_Source && (*(char *)_Source < ':'));
                _Source = (uint *)((int)_Source + 1)) {
            }
          }
        }
        if (cVar2 == '-') {
          DAT_01413f50 = (void *)-(int)DAT_01413f50;
        }
        DAT_01413f54 = (int)*(char *)_Source;
        if (DAT_01413f54 != 0) {
          _strncpy(PTR_DAT_01413fe0,(char *)_Source,3);
          PTR_DAT_01413fe0[3] = 0;
          return;
        }
        goto LAB_01409ad8;
      }
    }
    endCriticalFromID(0xc);
  }
  return;
}



bool __cdecl FUN_01409aee(int *param_1)

{
  bool bVar1;
  
  critical_code_area_executor(0xb);
  bVar1 = FUN_01409b0f(param_1);
  endCriticalFromID(0xb);
  return bVar1;
}



bool __cdecl FUN_01409b0f(int *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  if (DAT_01413f54 != 0) {
    uVar5 = param_1[5];
    if ((uVar5 != DAT_01413fe8) || (uVar5 != DAT_01413ff8)) {
      if (DAT_01415ae8 == 0) {
        FUN_01409cbb(1,1,uVar5,4,1,0,0,2,0,0,0);
        FUN_01409cbb(0,1,param_1[5],10,5,0,0,2,0,0,0);
      }
      else {
        if (DAT_01415b88 != 0) {
          uVar6 = (uint)DAT_01415b8e;
          uVar3 = 0;
          uVar4 = 0;
        }
        else {
          uVar3 = (uint)DAT_01415b8c;
          uVar6 = 0;
          uVar4 = (uint)DAT_01415b8e;
        }
        FUN_01409cbb(1,(uint)(DAT_01415b88 == 0),uVar5,(uint)DAT_01415b8a,uVar4,uVar3,uVar6,
                     (uint)DAT_01415b90,(uint)DAT_01415b92,(uint)DAT_01415b94,(uint)DAT_01415b96);
        if (DAT_01415b34 != 0) {
          uVar6 = (uint)DAT_01415b3a;
          uVar3 = 0;
          uVar4 = 0;
          uVar5 = param_1[5];
        }
        else {
          uVar3 = (uint)DAT_01415b38;
          uVar6 = 0;
          uVar4 = (uint)DAT_01415b3a;
          uVar5 = param_1[5];
        }
        FUN_01409cbb(0,(uint)(DAT_01415b34 == 0),uVar5,(uint)DAT_01415b36,uVar4,uVar3,uVar6,
                     (uint)DAT_01415b3c,(uint)DAT_01415b3e,(uint)DAT_01415b40,(uint)DAT_01415b42);
      }
    }
    iVar1 = param_1[7];
    if (DAT_01413fec < DAT_01413ffc) {
      if ((DAT_01413fec <= iVar1) && (iVar1 <= DAT_01413ffc)) {
        if ((DAT_01413fec < iVar1) && (iVar1 < DAT_01413ffc)) {
          return true;
        }
LAB_01409c87:
        iVar2 = ((param_1[2] * 0x3c + param_1[1]) * 0x3c + *param_1) * 1000;
        if (iVar1 == DAT_01413fec) {
          return DAT_01413ff0 <= iVar2;
        }
        return iVar2 < DAT_01414000;
      }
    }
    else {
      if (iVar1 < DAT_01413ffc) {
        return true;
      }
      if (DAT_01413fec < iVar1) {
        return true;
      }
      if ((iVar1 <= DAT_01413ffc) || (DAT_01413fec <= iVar1)) goto LAB_01409c87;
    }
  }
  return false;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl
FUN_01409cbb(int param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,int param_7,
            int param_8,int param_9,int param_10,int param_11)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == 1) {
    if ((param_3 & 3) == 0) {
      iVar1 = (&DAT_01414000)[param_4];
    }
    else {
      iVar1 = *(int *)(&DAT_01414034 + param_4 * 4);
    }
    iVar2 = (int)(param_3 * 0x16d + -0x63db + iVar1 + 1 + ((int)(param_3 - 1) >> 2)) % 7;
    if (param_6 < iVar2) {
      iVar1 = iVar1 + 1 + (param_5 * 7 - iVar2) + param_6;
    }
    else {
      iVar1 = iVar1 + -6 + (param_5 * 7 - iVar2) + param_6;
    }
    if (param_5 == 5) {
      if ((param_3 & 3) == 0) {
        iVar2 = *(int *)(&DAT_01414004 + param_4 * 4);
      }
      else {
        iVar2 = *(int *)(&DAT_01414038 + param_4 * 4);
      }
      if (iVar2 < iVar1) {
        iVar1 = iVar1 + -7;
      }
    }
  }
  else {
    if ((param_3 & 3) == 0) {
      iVar1 = (&DAT_01414000)[param_4];
    }
    else {
      iVar1 = *(int *)(&DAT_01414034 + param_4 * 4);
    }
    iVar1 = iVar1 + param_7;
  }
  if (param_1 == 1) {
    DAT_01413fe8 = param_3;
    DAT_01413ff0 = ((param_8 * 0x3c + param_9) * 0x3c + param_10) * 1000 + param_11;
    DAT_01413fec = iVar1;
  }
  else {
    DAT_01414000 = ((param_8 * 0x3c + param_9) * 0x3c + _DAT_01413f58 + param_10) * 1000 + param_11;
    if (DAT_01414000 < 0) {
      DAT_01414000 = DAT_01414000 + 86400000;
      DAT_01413ffc = iVar1 + -1;
    }
    else {
      DAT_01413ffc = iVar1;
      if (86399999 < DAT_01414000) {
        DAT_01414000 = DAT_01414000 + -86400000;
        DAT_01413ffc = iVar1 + 1;
      }
    }
    DAT_01413ff8 = param_3;
  }
  return;
}



void __thiscall FUN_01409dfb(void *this,byte *param_1,byte **param_2,undefined *param_3)

{
  FUN_01409e12(this,param_1,param_2,param_3,0);
  return;
}



undefined * __thiscall
FUN_01409e12(void *this,byte *param_1,byte **param_2,undefined *param_3,uint param_4)

{
  undefined *puVar1;
  uint uVar2;
  undefined *puVar3;
  uint uVar4;
  DWORD *pDVar5;
  byte bVar6;
  undefined *puVar7;
  undefined *local_c;
  byte *local_8;
  
  local_c = (undefined *)0x0;
  bVar6 = *param_1;
  local_8 = param_1 + 1;
  while( true ) {
    if (DAT_014139c4 < 2) {
      uVar2 = (byte)PTR_DAT_014137b8[(uint)bVar6 * 2] & 8;
      this = PTR_DAT_014137b8;
    }
    else {
      puVar7 = &DAT_00000008;
      uVar2 = FUN_01405ac0(this,(uint)bVar6,8);
      this = puVar7;
    }
    if (uVar2 == 0) break;
    bVar6 = *local_8;
    local_8 = local_8 + 1;
  }
  if (bVar6 == 0x2d) {
    param_4 = param_4 | 2;
LAB_01409e6d:
    bVar6 = *local_8;
    local_8 = local_8 + 1;
  }
  else if (bVar6 == 0x2b) goto LAB_01409e6d;
  if ((((int)param_3 < 0) || (param_3 == (undefined *)0x1)) || (0x24 < (int)param_3)) {
    if (param_2 != (byte **)0x0) {
      *param_2 = param_1;
    }
    return (undefined *)0x0;
  }
  puVar7 = (undefined *)0x10;
  if (param_3 == (undefined *)0x0) {
    if (bVar6 != 0x30) {
      param_3 = (undefined *)0xa;
      goto LAB_01409ed7;
    }
    if ((*local_8 != 0x78) && (*local_8 != 0x58)) {
      param_3 = &DAT_00000008;
      goto LAB_01409ed7;
    }
    param_3 = (undefined *)0x10;
  }
  if (((param_3 == (undefined *)0x10) && (bVar6 == 0x30)) &&
     ((*local_8 == 0x78 || (*local_8 == 0x58)))) {
    bVar6 = local_8[1];
    local_8 = local_8 + 2;
  }
LAB_01409ed7:
  puVar3 = (undefined *)(0xffffffff / ZEXT48(param_3));
  do {
    uVar2 = (uint)bVar6;
    if (DAT_014139c4 < 2) {
      uVar4 = (byte)PTR_DAT_014137b8[uVar2 * 2] & 4;
    }
    else {
      puVar1 = (undefined *)0x4;
      uVar4 = FUN_01405ac0(puVar7,uVar2,4);
      puVar7 = puVar1;
    }
    if (uVar4 == 0) {
      if (DAT_014139c4 < 2) {
        uVar2 = *(ushort *)(PTR_DAT_014137b8 + uVar2 * 2) & 0x103;
      }
      else {
        uVar2 = FUN_01405ac0(puVar7,uVar2,0x103);
      }
      if (uVar2 == 0) {
LAB_01409f83:
        local_8 = local_8 + -1;
        if ((param_4 & 8) == 0) {
          if (param_2 != (byte **)0x0) {
            local_8 = param_1;
          }
          local_c = (undefined *)0x0;
        }
        else if (((param_4 & 4) != 0) ||
                (((param_4 & 1) == 0 &&
                 ((((param_4 & 2) != 0 && ((undefined *)0x80000000 < local_c)) ||
                  (((param_4 & 2) == 0 && ((undefined *)0x7fffffff < local_c)))))))) {
          pDVar5 = FUN_01406c66();
          *pDVar5 = 0x22;
          if ((param_4 & 1) == 0) {
            local_c = (undefined *)(((param_4 & 2) != 0) + 0x7fffffff);
          }
          else {
            local_c = (undefined *)0xffffffff;
          }
        }
        if (param_2 != (byte **)0x0) {
          *param_2 = local_8;
        }
        if ((param_4 & 2) == 0) {
          return local_c;
        }
        return (undefined *)-(int)local_c;
      }
      uVar2 = FUN_0140a8f4((int)(char)bVar6);
      puVar7 = (undefined *)(uVar2 - 0x37);
    }
    else {
      puVar7 = (undefined *)((char)bVar6 + -0x30);
    }
    if (param_3 <= puVar7) goto LAB_01409f83;
    if ((local_c < puVar3) ||
       ((local_c == puVar3 && (puVar7 <= (undefined *)(0xffffffff % ZEXT48(param_3)))))) {
      local_c = puVar7 + (int)local_c * (int)param_3;
      param_4 = param_4 | 8;
    }
    else {
      param_4 = param_4 | 0xc;
    }
    bVar6 = *local_8;
    local_8 = local_8 + 1;
  } while( true );
}



// Library Function - Single Match
//  _strncmp
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  char cVar2;
  size_t sVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  char *pcVar7;
  
  sVar3 = _MaxCount;
  pcVar6 = _Str1;
  if (_MaxCount != 0) {
    do {
      if (sVar3 == 0) break;
      sVar3 = sVar3 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    iVar4 = _MaxCount - sVar3;
    do {
      pcVar6 = _Str2;
      pcVar7 = _Str1;
      if (iVar4 == 0) break;
      iVar4 = iVar4 + -1;
      pcVar7 = _Str1 + 1;
      pcVar6 = _Str2 + 1;
      cVar2 = *_Str1;
      cVar1 = *_Str2;
      _Str2 = pcVar6;
      _Str1 = pcVar7;
    } while (cVar1 == cVar2);
    uVar5 = 0;
    if ((byte)pcVar6[-1] <= (byte)pcVar7[-1]) {
      if (pcVar6[-1] == pcVar7[-1]) {
        return 0;
      }
      uVar5 = 0xfffffffe;
    }
    _MaxCount = ~uVar5;
  }
  return _MaxCount;
}



undefined4 __cdecl FUN_0140a068(int param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  BYTE *pBVar7;
  int iVar8;
  byte *pbVar9;
  int iVar10;
  byte *pbVar11;
  undefined4 uVar12;
  uint uVar13;
  undefined4 *puVar14;
  _cpinfo local_1c;
  uint local_8;
  
  critical_code_area_executor(0x19);
  CodePage = FUN_0140a215(param_1);
  if (CodePage != DAT_01415c78) {
    if (CodePage != 0) {
      iVar10 = 0;
      pUVar4 = &DAT_01414078;
LAB_0140a0a5:
      if (*pUVar4 != CodePage) goto code_r0x0140a0a9;
      local_8 = 0;
      puVar14 = (undefined4 *)&DAT_01415da0;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar14 = 0;
        puVar14 = puVar14 + 1;
      }
      *(undefined *)puVar14 = 0;
      pbVar11 = &DAT_01414088 + iVar10 * 0x30;
      do {
        bVar2 = *pbVar11;
        pbVar9 = pbVar11;
        while ((bVar2 != 0 && (bVar2 = pbVar9[1], bVar2 != 0))) {
          uVar13 = (uint)*pbVar9;
          if (uVar13 <= bVar2) {
            bVar3 = (&DAT_01414070)[local_8];
            do {
              (&DAT_01415da1)[uVar13] = (&DAT_01415da1)[uVar13] | bVar3;
              uVar13 = uVar13 + 1;
            } while (uVar13 <= bVar2);
          }
          pbVar9 = pbVar9 + 2;
          bVar2 = *pbVar9;
        }
        local_8 = local_8 + 1;
        pbVar11 = pbVar11 + 8;
      } while (local_8 < 4);
      DAT_01415c8c = 1;
      DAT_01415c78 = CodePage;
      DAT_01415ea4 = FUN_0140a25f(CodePage);
      DAT_01415c80 = (&DAT_0141407c)[iVar10 * 0xc];
      DAT_01415c84 = (&DAT_01414080)[iVar10 * 0xc];
      DAT_01415c88 = (&DAT_01414084)[iVar10 * 0xc];
      goto LAB_0140a1f9;
    }
    goto LAB_0140a1f4;
  }
  goto LAB_0140a08f;
code_r0x0140a0a9:
  pUVar4 = pUVar4 + 0xc;
  iVar10 = iVar10 + 1;
  if (0x1414167 < (int)pUVar4) goto code_r0x0140a0b4;
  goto LAB_0140a0a5;
code_r0x0140a0b4:
  BVar5 = GetCPInfo(CodePage,&local_1c);
  uVar13 = 1;
  if (BVar5 == 1) {
    DAT_01415ea4 = 0;
    puVar14 = (undefined4 *)&DAT_01415da0;
    for (iVar10 = 0x40; iVar10 != 0; iVar10 = iVar10 + -1) {
      *puVar14 = 0;
      puVar14 = puVar14 + 1;
    }
    *(undefined *)puVar14 = 0;
    if (local_1c.MaxCharSize < 2) {
      DAT_01415c8c = 0;
      DAT_01415c78 = CodePage;
    }
    else {
      DAT_01415c78 = CodePage;
      if (local_1c.LeadByte[0] != '\0') {
        pBVar7 = local_1c.LeadByte + 1;
        do {
          bVar2 = *pBVar7;
          if (bVar2 == 0) break;
          for (uVar6 = (uint)pBVar7[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
            (&DAT_01415da1)[uVar6] = (&DAT_01415da1)[uVar6] | 4;
          }
          pBVar1 = pBVar7 + 1;
          pBVar7 = pBVar7 + 2;
        } while (*pBVar1 != 0);
      }
      do {
        (&DAT_01415da1)[uVar13] = (&DAT_01415da1)[uVar13] | 8;
        uVar13 = uVar13 + 1;
      } while (uVar13 < 0xff);
      DAT_01415ea4 = FUN_0140a25f(CodePage);
      DAT_01415c8c = 1;
    }
    DAT_01415c80 = 0;
    DAT_01415c84 = 0;
    DAT_01415c88 = 0;
  }
  else {
    if (DAT_01415ba4 == 0) {
      uVar12 = 0xffffffff;
      goto LAB_0140a206;
    }
LAB_0140a1f4:
    FUN_0140a292();
  }
LAB_0140a1f9:
  FUN_0140a2bb();
LAB_0140a08f:
  uVar12 = 0;
LAB_0140a206:
  endCriticalFromID(0x19);
  return uVar12;
}



int __cdecl FUN_0140a215(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_01415ba4 = 1;
                    // WARNING: Could not recover jumptable at 0x0140a22f. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_01415ba4 = 1;
                    // WARNING: Could not recover jumptable at 0x0140a244. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_01415bd0;
  }
  DAT_01415ba4 = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_0140a25f(int param_1)

{
  if (param_1 == 0x3a4) {
    return 0x411;
  }
  if (param_1 == 0x3a8) {
    return 0x804;
  }
  if (param_1 == 0x3b5) {
    return 0x412;
  }
  if (param_1 != 0x3b6) {
    return 0;
  }
  return 0x404;
}



void FUN_0140a292(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_01415da0;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_01415c78 = 0;
  DAT_01415c8c = 0;
  DAT_01415ea4 = 0;
  DAT_01415c80 = 0;
  DAT_01415c84 = 0;
  DAT_01415c88 = 0;
  return;
}



void FUN_0140a2bb(void)

{
  BOOL BVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  ushort *puVar6;
  undefined uVar7;
  BYTE *pBVar8;
  undefined4 *puVar9;
  WORD local_518 [256];
  WCHAR local_318 [128];
  WCHAR local_218 [128];
  undefined4 local_118 [64];
  _cpinfo local_18;
  
  BVar1 = GetCPInfo(DAT_01415c78,&local_18);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)local_118 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    local_118[0]._0_1_ = 0x20;
    if (local_18.LeadByte[0] != 0) {
      pBVar8 = local_18.LeadByte + 1;
      do {
        uVar2 = (uint)local_18.LeadByte[0];
        if (uVar2 <= *pBVar8) {
          uVar4 = (*pBVar8 - uVar2) + 1;
          puVar9 = (undefined4 *)((int)local_118 + uVar2);
          for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
            *puVar9 = 0x20202020;
            puVar9 = puVar9 + 1;
          }
          for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
            *(undefined *)puVar9 = 0x20;
            puVar9 = (undefined4 *)((int)puVar9 + 1);
          }
        }
        local_18.LeadByte[0] = pBVar8[1];
        pBVar8 = pBVar8 + 2;
      } while (local_18.LeadByte[0] != 0);
    }
    FUN_01408701(1,(LPCSTR)local_118,0x100,local_518,DAT_01415c78,DAT_01415ea4,0);
    FUN_0140a46c(DAT_01415ea4,0x100,(char *)local_118,0x100,local_218,0x100,DAT_01415c78,0);
    FUN_0140a46c(DAT_01415ea4,0x200,(char *)local_118,0x100,local_318,0x100,DAT_01415c78,0);
    uVar2 = 0;
    puVar6 = local_518;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) != 0) {
          (&DAT_01415da1)[uVar2] = (&DAT_01415da1)[uVar2] | 0x20;
          uVar7 = *(undefined *)((int)local_318 + uVar2);
          goto LAB_0140a3c7;
        }
        (&DAT_01415ca0)[uVar2] = 0;
      }
      else {
        (&DAT_01415da1)[uVar2] = (&DAT_01415da1)[uVar2] | 0x10;
        uVar7 = *(undefined *)((int)local_218 + uVar2);
LAB_0140a3c7:
        (&DAT_01415ca0)[uVar2] = uVar7;
      }
      uVar2 = uVar2 + 1;
      puVar6 = puVar6 + 1;
    } while (uVar2 < 0x100);
  }
  else {
    uVar2 = 0;
    do {
      if ((uVar2 < 0x41) || (0x5a < uVar2)) {
        if ((0x60 < uVar2) && (uVar2 < 0x7b)) {
          (&DAT_01415da1)[uVar2] = (&DAT_01415da1)[uVar2] | 0x20;
          cVar3 = (char)uVar2 + -0x20;
          goto LAB_0140a411;
        }
        (&DAT_01415ca0)[uVar2] = 0;
      }
      else {
        (&DAT_01415da1)[uVar2] = (&DAT_01415da1)[uVar2] | 0x10;
        cVar3 = (char)uVar2 + ' ';
LAB_0140a411:
        (&DAT_01415ca0)[uVar2] = cVar3;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
  }
  return;
}



void FUN_0140a450(void)

{
  if (DAT_01416fe8 == 0) {
    FUN_0140a068(-3);
    DAT_01416fe8 = 1;
  }
  return;
}



int __cdecl
FUN_0140a46c(LCID param_1,uint param_2,char *param_3,int param_4,LPWSTR param_5,int param_6,
            UINT param_7,int param_8)

{
  int iVar1;
  int iVar2;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140f6c0;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_01415ba8 == 0) {
    iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_01415ba8 = 1;
      goto LAB_0140a4e2;
    }
    iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_01415ba8 = 2;
      goto LAB_0140a4e2;
    }
  }
  else {
LAB_0140a4e2:
    if (0 < param_4) {
      param_4 = FUN_0140a690(param_3,param_4);
    }
    if (DAT_01415ba8 == 2) {
      iVar1 = LCMapStringA(param_1,param_2,param_3,param_4,(LPSTR)param_5,param_6);
      goto LAB_0140a5fc;
    }
    if (DAT_01415ba8 == 1) {
      if (param_7 == 0) {
        param_7 = DAT_01415bd0;
      }
      iVar2 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,param_4,
                                  (LPWSTR)0x0,0);
      if (iVar2 != 0) {
        local_8 = 0;
        FUN_014028c0(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x3c) &&
           (iVar1 = MultiByteToWideChar(param_7,1,param_3,param_4,(LPWSTR)&stack0xffffffc4,iVar2),
           iVar1 != 0)) {
          iVar1 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,(LPWSTR)0x0,0);
          if (iVar1 != 0) {
            if ((param_2 & 0x400) == 0) {
              local_8 = 1;
              FUN_014028c0(unaff_DI);
              local_8 = 0xffffffff;
              if ((&stack0x00000000 != (undefined *)0x3c) &&
                 (iVar2 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,
                                       (LPWSTR)&stack0xffffffc4,iVar1), iVar2 != 0)) {
                if (param_6 == 0) {
                  param_6 = 0;
                  param_5 = (LPWSTR)0x0;
                }
                iVar1 = WideCharToMultiByte(param_7,0x220,(LPCWSTR)&stack0xffffffc4,iVar1,
                                            (LPSTR)param_5,param_6,(LPCSTR)0x0,(LPBOOL)0x0);
                iVar2 = iVar1;
joined_r0x0140a683:
                if (iVar2 != 0) goto LAB_0140a5fc;
              }
            }
            else {
              if (param_6 == 0) goto LAB_0140a5fc;
              if (iVar1 <= param_6) {
                iVar2 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,param_5,param_6
                                    );
                goto joined_r0x0140a683;
              }
            }
          }
        }
      }
    }
  }
  iVar1 = 0;
LAB_0140a5fc:
  *unaff_FS_OFFSET = local_14;
  return iVar1;
}



int __cdecl FUN_0140a690(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = param_1;
  iVar2 = param_2;
  if (param_2 != 0) {
    do {
      iVar2 = iVar2 + -1;
      if (*pcVar1 == '\0') break;
      pcVar1 = pcVar1 + 1;
    } while (iVar2 != 0);
  }
  if (*pcVar1 == '\0') {
    return (int)pcVar1 - (int)param_1;
  }
  return param_2;
}



uint __thiscall FUN_0140a6c0(void *this,byte *param_1,byte *param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  void *extraout_ECX;
  void *this_00;
  void *extraout_ECX_00;
  uint uVar7;
  uint uVar8;
  
  iVar2 = DAT_01415c74;
  if (DAT_01415bc0 == 0) {
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) goto LAB_0140a70e;
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar4 == bVar5);
      bVar3 = bVar5 + 0xbf + (-((byte)(bVar5 + 0xbf) < 0x1a) & 0x20U) + 0x41;
      bVar4 = bVar4 + 0xbf;
      bVar5 = bVar4 + (-(bVar4 < 0x1a) & 0x20U) + 0x41;
    } while (bVar5 == bVar3);
    bVar5 = (bVar5 < bVar3) * -2 + 1;
LAB_0140a70e:
    uVar6 = (uint)(char)bVar5;
  }
  else {
    LOCK();
    DAT_01415c74 = DAT_01415c74 + 1;
    UNLOCK();
    bVar1 = 0 < DAT_01415c70;
    if (bVar1) {
      LOCK();
      UNLOCK();
      DAT_01415c74 = iVar2;
      critical_code_area_executor(0x13);
      this = extraout_ECX;
    }
    uVar8 = (uint)bVar1;
    uVar6 = 0xff;
    uVar7 = 0;
    do {
      do {
        if ((char)uVar6 == '\0') goto LAB_0140a76f;
        bVar5 = *param_2;
        uVar6 = CONCAT31((int3)(uVar6 >> 8),bVar5);
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        uVar7 = CONCAT31((int3)(uVar7 >> 8),bVar4);
        param_1 = param_1 + 1;
      } while (bVar5 == bVar4);
      uVar7 = FUN_0140bb32(this,uVar7);
      uVar6 = FUN_0140bb32(this_00,uVar6);
      this = extraout_ECX_00;
    } while ((byte)uVar7 == (byte)uVar6);
    uVar7 = (uint)((byte)uVar7 < (byte)uVar6);
    uVar6 = (1 - uVar7) - (uint)(uVar7 != 0);
LAB_0140a76f:
    if (uVar8 == 0) {
      LOCK();
      DAT_01415c74 = DAT_01415c74 + -1;
      UNLOCK();
    }
    else {
      endCriticalFromID(0x13);
    }
  }
  return uVar6;
}



uint * __cdecl FUN_0140a790(uint *param_1,size_t param_2)

{
  uint *puVar1;
  
  critical_code_area_executor(0xc);
  puVar1 = FUN_0140a7e0(0,param_1,param_2);
  endCriticalFromID(0xc);
  return puVar1;
}



uint * __cdecl FUN_0140a7e0(uint param_1,uint *param_2,size_t param_3)

{
  int iVar1;
  DWORD *pDVar2;
  DWORD DVar3;
  uint uVar4;
  uint *puVar5;
  uint local_10c [65];
  LPSTR local_8;
  
  uVar4 = param_1;
  if (param_1 == 0) {
    DVar3 = GetCurrentDirectoryA(0x104,(LPSTR)local_10c);
  }
  else {
    iVar1 = FUN_0140a8b5(param_1);
    if (iVar1 == 0) {
      pDVar2 = FUN_01406c6f();
      *pDVar2 = 0xf;
      pDVar2 = FUN_01406c66();
      *pDVar2 = 0xd;
      return (uint *)0x0;
    }
    param_1 = (uint)CONCAT12(0x2e,CONCAT11(0x3a,(char)uVar4 + '@'));
    DVar3 = GetFullPathNameA((LPCSTR)&param_1,0x104,(LPSTR)local_10c,&local_8);
  }
  if ((DVar3 != 0) && (uVar4 = DVar3 + 1, uVar4 < 0x105)) {
    if (param_2 == (uint *)0x0) {
      if ((int)uVar4 <= (int)param_3) {
        uVar4 = param_3;
      }
      puVar5 = (uint *)_malloc(uVar4);
      if (puVar5 != (uint *)0x0) {
LAB_0140a8a1:
        puVar5 = FUN_014028f0(puVar5,local_10c);
        return puVar5;
      }
      pDVar2 = FUN_01406c66();
      *pDVar2 = 0xc;
    }
    else {
      puVar5 = param_2;
      if ((int)uVar4 <= (int)param_3) goto LAB_0140a8a1;
      pDVar2 = FUN_01406c66();
      *pDVar2 = 0x22;
    }
  }
  return (uint *)0x0;
}



undefined4 __cdecl FUN_0140a8b5(uint param_1)

{
  char cVar1;
  UINT UVar2;
  
  if (param_1 != 0) {
    cVar1 = (char)param_1;
    param_1 = (uint)CONCAT12(0x5c,CONCAT11(0x3a,cVar1 + '@'));
    UVar2 = GetDriveTypeA((LPCSTR)&param_1);
    if ((UVar2 == 0) || (UVar2 == 1)) {
      return 0;
    }
  }
  return 1;
}



uint __cdecl FUN_0140a8f4(uint param_1)

{
  void *extraout_ECX;
  bool bVar1;
  void *this;
  
  if (DAT_01415bc0 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      return param_1 - 0x20;
    }
  }
  else {
    InterlockedIncrement(&DAT_01415c74);
    bVar1 = DAT_01415c70 != 0;
    this = extraout_ECX;
    if (bVar1) {
      InterlockedDecrement(&DAT_01415c74);
      this = (void *)0x13;
      critical_code_area_executor(0x13);
    }
    param_1 = FUN_0140a963(this,param_1);
    if (bVar1) {
      endCriticalFromID(0x13);
    }
    else {
      InterlockedDecrement(&DAT_01415c74);
    }
  }
  return param_1;
}



uint __thiscall FUN_0140a963(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  void *local_8;
  
  uVar1 = param_1;
  if (DAT_01415bc0 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      uVar1 = param_1 - 0x20;
    }
  }
  else {
    local_8 = this;
    if ((int)param_1 < 0x100) {
      if (DAT_014139c4 < 2) {
        uVar2 = (byte)PTR_DAT_014137b8[param_1 * 2] & 2;
      }
      else {
        uVar2 = FUN_01405ac0(this,param_1,2);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((PTR_DAT_014137b8[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
      iVar3 = 1;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      iVar3 = 2;
    }
    iVar3 = FUN_0140a46c(DAT_01415bc0,0x200,(char *)&param_1,iVar3,(LPWSTR)&local_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = (uint)local_8 & 0xff;
      }
      else {
        uVar1 = (uint)local_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



byte * __cdecl FUN_0140aa30(byte *param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *param_2;
    if (bVar1 == 0) break;
    param_2 = param_2 + 1;
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = param_1;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (byte *)(uint)bVar1;
    }
    param_1 = pbVar2 + 1;
  } while ((*(byte *)((int)&uStack_28 + ((int)(byte *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return pbVar2;
}



undefined4 __cdecl FUN_0140aa6a(LPCSTR param_1,byte param_2)

{
  DWORD DVar1;
  DWORD *pDVar2;
  
  DVar1 = GetFileAttributesA(param_1);
  if (DVar1 == 0xffffffff) {
    DVar1 = GetLastError();
    FUN_01406bf3(DVar1);
  }
  else {
    if (((DVar1 & 1) == 0) || ((param_2 & 2) == 0)) {
      return 0;
    }
    pDVar2 = FUN_01406c66();
    *pDVar2 = 0xd;
    pDVar2 = FUN_01406c6f();
    *pDVar2 = 5;
  }
  return 0xffffffff;
}



uint * __cdecl FUN_0140aab0(uint *param_1,uint param_2)

{
  byte bVar1;
  uint *puVar2;
  uint uVar3;
  
  if (DAT_01415c8c == 0) {
    puVar2 = FUN_014031d0(param_1,(char)param_2);
  }
  else {
    critical_code_area_executor(0x19);
    while( true ) {
      bVar1 = *(byte *)param_1;
      uVar3 = (uint)bVar1;
      if (bVar1 == 0) break;
      if (((&DAT_01415da1)[uVar3] & 4) == 0) {
        puVar2 = param_1;
        if (param_2 == uVar3) break;
      }
      else {
        puVar2 = (uint *)((int)param_1 + 1);
        if (*(byte *)((int)param_1 + 1) == 0) {
          endCriticalFromID(0x19);
          return (uint *)0x0;
        }
        if (param_2 == CONCAT11(bVar1,*(byte *)((int)param_1 + 1))) {
          endCriticalFromID(0x19);
          return param_1;
        }
      }
      param_1 = (uint *)((int)puVar2 + 1);
    }
    endCriticalFromID(0x19);
    puVar2 = (uint *)(~-(uint)(param_2 != uVar3) & (uint)param_1);
  }
  return puVar2;
}



char * __cdecl FUN_0140ab47(int param_1,LPCSTR param_2,char *param_3,LPVOID param_4)

{
  undefined4 *puVar1;
  byte bVar2;
  char *pcVar3;
  undefined4 *puVar5;
  DWORD *pDVar6;
  BOOL BVar7;
  DWORD DVar8;
  uint uVar9;
  uint *puVar10;
  int iVar11;
  uint uVar12;
  _STARTUPINFOA local_64;
  _PROCESS_INFORMATION local_20;
  char *local_10;
  DWORD local_c;
  char local_5;
  char *pcVar4;
  
  local_5 = '\0';
  local_c = 0;
  if ((param_1 != 0) && (param_1 != 1)) {
    if (param_1 < 2) {
LAB_0140ab97:
      pDVar6 = FUN_01406c66();
      *pDVar6 = 0x16;
      pDVar6 = FUN_01406c6f();
      *pDVar6 = 0;
      return (char *)0xffffffff;
    }
    if (3 < param_1) {
      if (param_1 != 4) goto LAB_0140ab97;
      local_5 = '\x01';
    }
  }
  local_10 = param_3;
  pcVar3 = param_3;
  while (*pcVar3 != '\0') {
    do {
      pcVar4 = pcVar3;
      pcVar3 = pcVar4 + 1;
    } while (*pcVar3 != '\0');
    if (pcVar4[2] != '\0') {
      *pcVar3 = ' ';
      pcVar3 = pcVar4 + 2;
    }
  }
  Initialize_Memory(&local_64,0,0x44);
  local_64.cb = 0x44;
  uVar12 = DAT_01415fc0;
  uVar9 = DAT_01415fc0;
  while ((uVar12 != 0 &&
         (uVar9 = uVar9 - 1,
         *(char *)((&DAT_01415ec0)[(int)uVar9 >> 5] + 4 + (uVar9 & 0x1f) * 0x24) == '\0'))) {
    uVar12 = uVar12 - 1;
  }
  uVar9 = uVar12 * 5 + 4;
  local_64.cbReserved2 = (WORD)uVar9;
  local_64.lpReserved2 = (LPBYTE)Allocate_Memory(uVar9 & 0xffff,1);
  *(uint *)local_64.lpReserved2 = uVar12;
  uVar9 = 0;
  puVar10 = (uint *)((int)local_64.lpReserved2 + 4);
  puVar5 = (undefined4 *)((int)local_64.lpReserved2 + uVar12 + 4);
  if (0 < (int)uVar12) {
    do {
      puVar1 = (undefined4 *)((&DAT_01415ec0)[(int)uVar9 >> 5] + (uVar9 & 0x1f) * 0x24);
      bVar2 = *(byte *)(puVar1 + 1);
      if ((bVar2 & 0x10) == 0) {
        *(byte *)puVar10 = bVar2;
        *puVar5 = *puVar1;
      }
      else {
        *(byte *)puVar10 = 0;
        *puVar5 = 0xffffffff;
      }
      uVar9 = uVar9 + 1;
      puVar10 = (uint *)((int)puVar10 + 1);
      puVar5 = puVar5 + 1;
    } while ((int)uVar9 < (int)uVar12);
  }
  if (local_5 != '\0') {
    puVar10 = (uint *)((int)local_64.lpReserved2 + 4);
    iVar11 = 0;
    puVar5 = (undefined4 *)((int)local_64.lpReserved2 + uVar12 + 4);
    while( true ) {
      uVar9 = uVar12;
      if (2 < (int)uVar12) {
        uVar9 = 3;
      }
      if ((int)uVar9 <= iVar11) break;
      *(undefined *)puVar10 = 0;
      *puVar5 = 0xffffffff;
      iVar11 = iVar11 + 1;
      puVar10 = (uint *)((int)puVar10 + 1);
      puVar5 = puVar5 + 1;
    }
    local_c = 8;
  }
  pDVar6 = FUN_01406c66();
  *pDVar6 = 0;
  pDVar6 = FUN_01406c6f();
  *pDVar6 = 0;
  BVar7 = CreateProcessA(param_2,local_10,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,1,
                         local_c,param_4,(LPCSTR)0x0,&local_64,&local_20);
  DVar8 = GetLastError();
  FUN_01404c4e(local_64.lpReserved2);
  if (BVar7 == 0) {
    FUN_01406bf3(DVar8);
    return (char *)0xffffffff;
  }
  if (param_1 == 2) {
                    // WARNING: Subroutine does not return
    __exit1(0);
  }
  if (param_1 == 0) {
    WaitForSingleObject(local_20.hProcess,0xffffffff);
    GetExitCodeProcess(local_20.hProcess,(LPDWORD)&param_3);
    CloseHandle(local_20.hProcess);
  }
  else if (param_1 == 4) {
    CloseHandle(local_20.hProcess);
    param_3 = (char *)0x0;
  }
  else {
    param_3 = (char *)local_20.hProcess;
  }
  CloseHandle(local_20.hThread);
  return param_3;
}



undefined4 __cdecl FUN_0140ad30(uint **param_1,uint **param_2,uint **param_3,uint **param_4)

{
  size_t sVar1;
  uint *puVar2;
  size_t sVar3;
  char *pcVar4;
  DWORD *pDVar5;
  undefined4 uVar6;
  char cVar7;
  uint **ppuVar8;
  size_t sVar9;
  undefined4 *_Str;
  uint **ppuVar10;
  
  sVar9 = 2;
  sVar3 = sVar9;
  for (ppuVar8 = param_1; *ppuVar8 != (uint *)0x0; ppuVar8 = ppuVar8 + 1) {
    sVar1 = _strlen((char *)*ppuVar8);
    sVar3 = sVar3 + 1 + sVar1;
  }
  puVar2 = (uint *)_malloc(sVar3);
  *param_3 = puVar2;
  if (puVar2 == (uint *)0x0) {
    *param_4 = (uint *)0x0;
LAB_0140ae51:
    pDVar5 = FUN_01406c66();
    *pDVar5 = 0xc;
    pDVar5 = FUN_01406c6f();
    *pDVar5 = 8;
LAB_0140ae67:
    uVar6 = 0xffffffff;
  }
  else {
    ppuVar8 = param_2;
    if (param_2 == (uint **)0x0) {
      *param_4 = (uint *)0x0;
      ppuVar8 = param_4;
      ppuVar10 = param_4;
    }
    else {
      for (; *ppuVar8 != (uint *)0x0; ppuVar8 = ppuVar8 + 1) {
        sVar3 = _strlen((char *)*ppuVar8);
        sVar9 = sVar9 + 1 + sVar3;
      }
      if (DAT_01415910 == (undefined4 *)0x0) {
        DAT_01415910 = FUN_0140806a();
        if (DAT_01415910 != (undefined4 *)0x0) goto LAB_0140adce;
        goto LAB_0140ae67;
      }
LAB_0140adce:
      ppuVar8 = (uint **)0x0;
      if (*(char *)DAT_01415910 != '\0') {
        cVar7 = *(char *)DAT_01415910;
        _Str = DAT_01415910;
        do {
          if (cVar7 == '=') break;
          sVar3 = _strlen((char *)_Str);
          ppuVar8 = (uint **)((int)ppuVar8 + sVar3 + 1);
          cVar7 = *(char *)((int)DAT_01415910 + (int)ppuVar8);
          _Str = (undefined4 *)((int)DAT_01415910 + (int)ppuVar8);
        } while (cVar7 != '\0');
      }
      pcVar4 = (char *)((int)DAT_01415910 + (int)ppuVar8);
      ppuVar10 = ppuVar8;
      while ((((*pcVar4 == '=' && (pcVar4[1] != '\0')) && (pcVar4[2] == ':')) && (pcVar4[3] == '='))
            ) {
        sVar3 = _strlen(pcVar4 + 4);
        ppuVar10 = (uint **)((int)ppuVar10 + sVar3 + 5);
        pcVar4 = (char *)((int)DAT_01415910 + (int)ppuVar10);
      }
      puVar2 = (uint *)_malloc((int)ppuVar10 + (sVar9 - (int)ppuVar8));
      *param_4 = puVar2;
      if (puVar2 == (uint *)0x0) {
        FUN_01404c4e((undefined *)*param_3);
        *param_3 = (uint *)0x0;
        goto LAB_0140ae51;
      }
    }
    puVar2 = *param_3;
    param_3 = param_1;
    if (*param_1 != (uint *)0x0) {
      FUN_014028f0(puVar2,*param_1);
      param_3 = param_1 + 1;
      sVar3 = _strlen((char *)*param_1);
      puVar2 = (uint *)((int)puVar2 + sVar3 + 1);
      goto LAB_0140ae8e;
    }
    while( true ) {
      puVar2 = (uint *)((int)puVar2 + 1);
LAB_0140ae8e:
      if (*param_3 == (uint *)0x0) break;
      FUN_014028f0(puVar2,*param_3);
      sVar3 = _strlen((char *)*param_3);
      puVar2 = (uint *)((int)puVar2 + sVar3);
      *(undefined *)puVar2 = 0x20;
      param_3 = param_3 + 1;
    }
    *(undefined *)((int)puVar2 + -1) = 0;
    *(undefined *)puVar2 = 0;
    puVar2 = *param_4;
    if (param_2 != (uint **)0x0) {
      FUN_01402ad0(puVar2,(undefined4 *)((int)DAT_01415910 + (int)ppuVar8),
                   (int)ppuVar10 - (int)ppuVar8);
      puVar2 = (uint *)((int)puVar2 + ((int)ppuVar10 - (int)ppuVar8));
      for (; *param_2 != (uint *)0x0; param_2 = param_2 + 1) {
        FUN_014028f0(puVar2,*param_2);
        sVar3 = _strlen((char *)*param_2);
        puVar2 = (uint *)((int)puVar2 + sVar3 + 1);
      }
    }
    if (puVar2 != (uint *)0x0) {
      if (puVar2 == *param_4) {
        *(undefined *)puVar2 = 0;
        puVar2 = (uint *)((int)puVar2 + 1);
      }
      *(undefined *)puVar2 = 0;
    }
    FUN_01404c4e((undefined *)DAT_01415910);
    DAT_01415910 = (undefined4 *)0x0;
    uVar6 = 0;
  }
  return uVar6;
}



void __cdecl FUN_0140afca(byte param_1)

{
  FUN_0140b013(param_1,0,4);
  return;
}



undefined4 __cdecl FUN_0140b013(byte param_1,uint param_2,byte param_3)

{
  uint uVar1;
  
  if (((&DAT_01415da1)[param_1] & param_3) == 0) {
    if (param_2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(ushort *)(&DAT_014137c2 + (uint)param_1 * 2) & param_2;
    }
    if (uVar1 == 0) {
      return 0;
    }
  }
  return 1;
}



int __cdecl Window_MessageBox_Manager(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE user32_dll;
  int msgBox;
  
  msgBox = 0;
  if (MessageBox == (FARPROC)0x0) {
    user32_dll = LoadLibraryA("user32.dll");
    if (user32_dll != (HMODULE)0x0) {
      MessageBox = GetProcAddress(user32_dll,"MessageBoxA");
      if (MessageBox != (FARPROC)0x0) {
        ActiveWindow = GetProcAddress(user32_dll,"GetActiveWindow");
        LastActivePopup = GetProcAddress(user32_dll,"GetLastActivePopup");
        goto LAB_0140b093;
      }
    }
    msgBox = 0;
  }
  else {
LAB_0140b093:
    if (ActiveWindow != (FARPROC)0x0) {
      msgBox = (*ActiveWindow)();
      if ((msgBox != 0) && (LastActivePopup != (FARPROC)0x0)) {
        msgBox = (*LastActivePopup)(msgBox);
      }
    }
    msgBox = (*MessageBox)(msgBox,param_1,param_2,param_3);
  }
  return msgBox;
}



void FUN_0140b0cd(void)

{
  __amsg_exit(2);
  return;
}



uint * __cdecl FUN_0140b0d6(int param_1,uint *param_2)

{
  uint *puVar1;
  byte *pbVar2;
  size_t sVar3;
  int iVar4;
  int iVar5;
  undefined **ppuVar6;
  char **ppcVar7;
  uint local_8c [33];
  size_t local_8;
  
  iVar5 = 0;
  if ((param_1 < 0) || (5 < param_1)) {
    return (uint *)0x0;
  }
  critical_code_area_executor(0x13);
  DAT_01415c70 = DAT_01415c70 + 1;
  while (DAT_01415c74 != 0) {
    Sleep(1);
  }
  if (param_1 == 0) {
    local_8 = 1;
    param_1 = 0;
    if (param_2 == (uint *)0x0) {
LAB_0140b2fc:
      puVar1 = FUN_0140b437();
    }
    else {
      if (((*(char *)param_2 == 'L') && (*(char *)((int)param_2 + 1) == 'C')) &&
         (*(char *)((int)param_2 + 2) == '_')) {
        pbVar2 = FUN_0140aa30((byte *)param_2,&DAT_0140f758);
        puVar1 = param_2;
        while (((pbVar2 != (byte *)0x0 && (local_8 = (int)pbVar2 - (int)puVar1, local_8 != 0)) &&
               (*pbVar2 != 0x3b))) {
          param_2 = (uint *)0x1;
          ppuVar6 = &PTR_s_LC_COLLATE_0141428c;
          do {
            iVar5 = _strncmp(*ppuVar6,(char *)puVar1,local_8);
            if ((iVar5 == 0) && (sVar3 = _strlen(*ppuVar6), local_8 == sVar3)) break;
            param_2 = (uint *)((int)param_2 + 1);
            ppuVar6 = ppuVar6 + 3;
          } while ((int)ppuVar6 < 0x14142bd);
          pbVar2 = pbVar2 + 1;
          sVar3 = FUN_0140c840(pbVar2,&DAT_0140f754);
          if ((sVar3 == 0) && (*pbVar2 != 0x3b)) break;
          if ((int)param_2 < 6) {
            _strncpy((char *)local_8c,(char *)pbVar2,sVar3);
            *(undefined *)((int)local_8c + sVar3) = 0;
            iVar5 = FUN_0140b31c((int)param_2,local_8c);
            if (iVar5 != 0) {
              param_1 = param_1 + 1;
            }
          }
          if ((pbVar2[sVar3] == 0) || (puVar1 = (uint *)(pbVar2 + sVar3 + 1), *(byte *)puVar1 == 0))
          goto LAB_0140b266;
          pbVar2 = FUN_0140aa30((byte *)puVar1,&DAT_0140f758);
        }
        endCriticalFromID(0x13);
        puVar1 = (uint *)0x0;
        goto LAB_0140b30b;
      }
      puVar1 = FUN_0140b4f0(param_2,local_8c,(undefined4 *)0x0,(undefined4 *)0x0);
      if (puVar1 != (uint *)0x0) {
        ppcVar7 = &DAT_01414284;
        do {
          if (ppcVar7 != &DAT_01414284) {
            iVar4 = _strcmp((char *)local_8c,*ppcVar7);
            if ((iVar4 == 0) || (iVar4 = FUN_0140b31c(iVar5,local_8c), iVar4 != 0)) {
              param_1 = param_1 + 1;
            }
            else {
              local_8 = 0;
            }
          }
          ppcVar7 = ppcVar7 + 3;
          iVar5 = iVar5 + 1;
        } while ((int)ppcVar7 < 0x14142c1);
        if (local_8 == 0) {
LAB_0140b266:
          if (param_1 != 0) goto LAB_0140b2fc;
          puVar1 = (uint *)0x0;
        }
        else {
          puVar1 = FUN_0140b437();
          FUN_01404c4e(DAT_01414284);
          DAT_01414284 = (undefined *)0x0;
        }
      }
    }
  }
  else if (param_2 == (uint *)0x0) {
    puVar1 = (uint *)(&DAT_01414284)[param_1 * 3];
  }
  else {
    puVar1 = (uint *)FUN_0140b31c(param_1,param_2);
  }
  endCriticalFromID(0x13);
LAB_0140b30b:
  DAT_01415c70 = DAT_01415c70 + -1;
  return puVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0140b31c(int param_1,uint *param_2)

{
  uint *puVar1;
  undefined *puVar2;
  uint *puVar3;
  size_t sVar4;
  uint *puVar5;
  int iVar6;
  uint local_a8 [33];
  undefined4 local_24 [2];
  undefined4 local_1c;
  uint local_18;
  ushort local_14;
  undefined4 *local_c;
  undefined4 local_8;
  
  puVar3 = FUN_0140b4f0(param_2,local_a8,(undefined4 *)&local_14,&local_1c);
  if (puVar3 != (uint *)0x0) {
    sVar4 = _strlen((char *)local_a8);
    puVar3 = (uint *)_malloc(sVar4 + 1);
    if (puVar3 != (uint *)0x0) {
      puVar1 = (uint *)(&DAT_01415bb8 + param_1 * 4);
      puVar2 = (undefined *)(&DAT_01414284)[param_1 * 3];
      local_18 = *puVar1;
      local_c = (undefined4 *)(&DAT_01415c04 + param_1 * 6);
      FUN_01402ad0(local_24,local_c,6);
      local_8 = DAT_01415bd0;
      puVar5 = FUN_014028f0(puVar3,local_a8);
      (&DAT_01414284)[param_1 * 3] = puVar5;
      *puVar1 = (uint)local_14;
      FUN_01402ad0(local_c,(undefined4 *)&local_14,6);
      if (param_1 == 2) {
        DAT_01415bd0 = local_1c;
      }
      if (param_1 == 1) {
        _DAT_01415bd4 = local_1c;
      }
      iVar6 = (**(code **)(&DAT_01414288 + param_1 * 0xc))();
      if (iVar6 == 0) {
        if (puVar2 != &DAT_01414174) {
          FUN_01404c4e(puVar2);
        }
        return (&DAT_01414284)[param_1 * 3];
      }
      (&DAT_01414284)[param_1 * 3] = puVar2;
      FUN_01404c4e((undefined *)puVar3);
      *puVar1 = local_18;
      DAT_01415bd0 = local_8;
    }
  }
  return 0;
}



uint * FUN_0140b437(void)

{
  bool bVar1;
  int iVar2;
  char **ppcVar3;
  char **ppcVar4;
  
  bVar1 = true;
  if (DAT_01414284 == (uint *)0x0) {
    DAT_01414284 = (uint *)_malloc(0x351);
  }
  *(undefined *)DAT_01414284 = 0;
  FUN_0140b60b(DAT_01414284,3);
  ppcVar3 = &PTR_DAT_01414290;
  do {
    FUN_01402900(DAT_01414284,(uint *)&DAT_0140f754);
    ppcVar4 = ppcVar3 + 3;
    iVar2 = _strcmp(*ppcVar3,ppcVar3[3]);
    if (iVar2 != 0) {
      bVar1 = false;
    }
    FUN_0140b60b(DAT_01414284,3);
    ppcVar3 = ppcVar4;
  } while ((int)ppcVar4 < 0x14142c0);
  if (!bVar1) {
    return DAT_01414284;
  }
  FUN_01404c4e((undefined *)DAT_01414284);
  DAT_01414284 = (uint *)0x0;
  return (uint *)PTR_DAT_0141429c;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * __cdecl FUN_0140b4f0(uint *param_1,uint *param_2,undefined4 *param_3,undefined4 *param_4)

{
  int iVar1;
  uint *puVar2;
  uint local_8c [34];
  
  if (param_1 == (uint *)0x0) {
LAB_0140b596:
    puVar2 = (uint *)0x0;
  }
  else {
    if ((*(char *)param_1 == 'C') && (*(char *)((int)param_1 + 1) == '\0')) {
      *(undefined *)((int)param_2 + 1) = 0;
      *(undefined *)param_2 = 0x43;
      if (param_3 != (undefined4 *)0x0) {
        *(undefined2 *)param_3 = 0;
        *(undefined2 *)((int)param_3 + 2) = 0;
        *(undefined2 *)(param_3 + 1) = 0;
      }
      if (param_4 == (undefined4 *)0x0) {
        return param_2;
      }
      *param_4 = 0;
      return param_2;
    }
    iVar1 = _strcmp(&DAT_014141fc,(char *)param_1);
    if ((iVar1 != 0) && (iVar1 = _strcmp(&DAT_01414178,(char *)param_1), iVar1 != 0)) {
      puVar2 = param_1;
      iVar1 = FUN_0140b630((char *)local_8c,(byte *)param_1);
      if ((iVar1 != 0) ||
         (iVar1 = FUN_0140c87e(puVar2,(char *)local_8c,(undefined2 *)&DAT_01415bd8,(int)local_8c),
         iVar1 == 0)) goto LAB_0140b596;
      _DAT_01415be0 = (uint)DAT_01415bdc;
      FUN_0140b6fc((uint *)&DAT_014141fc,local_8c);
      if (*(char *)param_1 == '\0') {
        param_1 = (uint *)&DAT_014141fc;
      }
      FUN_014028f0((uint *)&DAT_01414178,param_1);
    }
    if (param_3 != (undefined4 *)0x0) {
      FUN_01402ad0(param_3,(undefined4 *)&DAT_01415bd8,6);
    }
    if (param_4 != (undefined4 *)0x0) {
      FUN_01402ad0(param_4,(undefined4 *)&DAT_01415be0,4);
    }
    FUN_014028f0(param_2,(uint *)&DAT_014141fc);
    puVar2 = (uint *)&DAT_014141fc;
  }
  return puVar2;
}



void __cdecl FUN_0140b60b(uint *param_1,int param_2)

{
  uint **ppuVar1;
  int *piVar2;
  int iVar3;
  
  if (0 < param_2) {
    piVar2 = &param_2;
    iVar3 = param_2;
    do {
      ppuVar1 = (uint **)(piVar2 + 1);
      piVar2 = piVar2 + 1;
      FUN_01402900(param_1,*ppuVar1);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return;
}



undefined4 __cdecl FUN_0140b630(char *param_1,byte *param_2)

{
  byte bVar1;
  size_t _Count;
  byte *_Source;
  char *_Dest;
  
  _Source = param_2;
  Initialize_Memory(param_1,0,0x88);
  if (*param_2 != 0) {
    if ((*param_2 != 0x2e) || (param_2[1] == 0)) {
      param_2 = (byte *)0x0;
      while( true ) {
        _Count = FUN_0140c840(_Source,&DAT_0140f760);
        if (_Count == 0) {
          return 0xffffffff;
        }
        bVar1 = _Source[_Count];
        if (param_2 == (byte *)0x0) {
          if (0x3f < (int)_Count) {
            return 0xffffffff;
          }
          _Dest = param_1;
          if (bVar1 == 0x2e) {
            return 0xffffffff;
          }
        }
        else if (param_2 == (byte *)0x1) {
          if (0x3f < (int)_Count) {
            return 0xffffffff;
          }
          if (bVar1 == 0x5f) {
            return 0xffffffff;
          }
          _Dest = param_1 + 0x40;
        }
        else {
          if (param_2 != (byte *)0x2) {
            return 0xffffffff;
          }
          if ((bVar1 != 0) && (bVar1 != 0x2c)) {
            return 0xffffffff;
          }
          _Dest = param_1 + 0x80;
        }
        _strncpy(_Dest,(char *)_Source,_Count);
        if (bVar1 == 0x2c) {
          return 0;
        }
        if (bVar1 == 0) break;
        param_2 = param_2 + 1;
        _Source = _Source + _Count + 1;
      }
      return 0;
    }
    FUN_014028f0((uint *)(param_1 + 0x80),(uint *)(param_2 + 1));
  }
  return 0;
}



void __cdecl FUN_0140b6fc(uint *param_1,uint *param_2)

{
  FUN_014028f0(param_1,param_2);
  if (*(char *)(param_2 + 0x10) != '\0') {
    FUN_0140b60b(param_1,2);
  }
  if (*(char *)(param_2 + 0x20) != '\0') {
    FUN_0140b60b(param_1,2);
  }
  return;
}



int __cdecl FUN_0140b74f(uint param_1,int param_2)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01408d0f(param_1);
    iVar1 = FUN_0140b7a8(param_1,param_2);
    FUN_01408d6e(param_1);
    return iVar1;
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  return -1;
}



int __cdecl FUN_0140b7a8(uint param_1,int param_2)

{
  DWORD DVar1;
  DWORD DVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  DWORD *pDVar6;
  HANDLE hFile;
  BOOL BVar7;
  undefined1 unaff_BP;
  int iVar8;
  uint uVar9;
  char local_1008 [4064];
  undefined4 uStackY_28;
  
  FUN_014028c0(unaff_BP);
  iVar8 = 0;
  DVar1 = FUN_014097b0(param_1,0,1);
  if ((DVar1 == 0xffffffff) || (DVar2 = FUN_014097b0(param_1,0,2), DVar2 == 0xffffffff)) {
    iVar8 = -1;
  }
  else {
    uVar9 = param_2 - DVar2;
    if ((int)uVar9 < 1) {
      if ((int)uVar9 < 0) {
        FUN_014097b0(param_1,param_2,0);
        hFile = (HANDLE)FUN_01408c26(param_1);
        BVar7 = SetEndOfFile(hFile);
        iVar8 = (BVar7 != 0) - 1;
        if (iVar8 == -1) {
          pDVar6 = FUN_01406c66();
          *pDVar6 = 0xd;
          DVar2 = GetLastError();
          pDVar6 = FUN_01406c6f();
          *pDVar6 = DVar2;
        }
      }
    }
    else {
      Initialize_Memory(local_1008,0,0x1000);
      uStackY_28 = 0x140b815;
      iVar3 = FUN_0140d17e(param_1,0x8000);
      do {
        uVar4 = 0x1000;
        if ((int)uVar9 < 0x1000) {
          uVar4 = uVar9;
        }
        iVar5 = FUN_01408e88(param_1,local_1008,uVar4);
        if (iVar5 == -1) {
          pDVar6 = FUN_01406c6f();
          if (*pDVar6 == 5) {
            pDVar6 = FUN_01406c66();
            *pDVar6 = 0xd;
          }
          iVar8 = -1;
          break;
        }
        uVar9 = uVar9 - iVar5;
      } while (0 < (int)uVar9);
      FUN_0140d17e(param_1,iVar3);
    }
    FUN_014097b0(param_1,DVar1,0);
  }
  return iVar8;
}



int __thiscall FUN_0140b8cd(void *this,byte *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  undefined *puVar6;
  
  while( true ) {
    if (DAT_014139c4 < 2) {
      uVar1 = (byte)PTR_DAT_014137b8[(uint)*param_1 * 2] & 8;
      this = PTR_DAT_014137b8;
    }
    else {
      puVar6 = &DAT_00000008;
      uVar1 = FUN_01405ac0(this,(uint)*param_1,8);
      this = puVar6;
    }
    if (uVar1 == 0) break;
    param_1 = param_1 + 1;
  }
  uVar1 = (uint)*param_1;
  pbVar5 = param_1 + 1;
  if ((uVar1 == 0x2d) || (uVar4 = uVar1, uVar1 == 0x2b)) {
    uVar4 = (uint)*pbVar5;
    pbVar5 = param_1 + 2;
  }
  iVar3 = 0;
  while( true ) {
    if (DAT_014139c4 < 2) {
      uVar2 = (byte)PTR_DAT_014137b8[uVar4 * 2] & 4;
    }
    else {
      puVar6 = (undefined *)0x4;
      uVar2 = FUN_01405ac0(this,uVar4,4);
      this = puVar6;
    }
    if (uVar2 == 0) break;
    iVar3 = (uVar4 - 0x30) + iVar3 * 10;
    uVar4 = (uint)*pbVar5;
    pbVar5 = pbVar5 + 1;
  }
  if (uVar1 == 0x2d) {
    iVar3 = -iVar3;
  }
  return iVar3;
}



uchar * __cdecl FUN_0140ba3e(uchar *param_1)

{
  int iVar1;
  size_t _MaxCount;
  size_t sVar2;
  uchar **ppuVar3;
  
  if (((DAT_01416fe4 != 0) &&
      ((DAT_0141593c != (uchar **)0x0 ||
       (((DAT_01415944 != 0 && (iVar1 = FUN_0140d253(), iVar1 == 0)) &&
        (DAT_0141593c != (uchar **)0x0)))))) && (ppuVar3 = DAT_0141593c, param_1 != (uchar *)0x0)) {
    _MaxCount = _strlen((char *)param_1);
    for (; *ppuVar3 != (uchar *)0x0; ppuVar3 = ppuVar3 + 1) {
      sVar2 = _strlen((char *)*ppuVar3);
      if (((_MaxCount < sVar2) && ((*ppuVar3)[_MaxCount] == '=')) &&
         (iVar1 = __mbsnbicoll(*ppuVar3,param_1,_MaxCount), iVar1 == 0)) {
        return *ppuVar3 + _MaxCount + 1;
      }
    }
  }
  return (uchar *)0x0;
}



uint __thiscall FUN_0140bb32(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  void *local_8;
  
  uVar1 = param_1;
  if (DAT_01415bc0 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      uVar1 = param_1 + 0x20;
    }
  }
  else {
    iVar3 = 1;
    local_8 = this;
    if ((int)param_1 < 0x100) {
      if (DAT_014139c4 < 2) {
        uVar2 = (byte)PTR_DAT_014137b8[param_1 * 2] & 1;
      }
      else {
        uVar2 = FUN_01405ac0(this,param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((PTR_DAT_014137b8[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      iVar3 = 2;
    }
    iVar3 = FUN_0140a46c(DAT_01415bc0,0x100,(char *)&param_1,iVar3,(LPWSTR)&local_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = (uint)local_8 & 0xff;
      }
      else {
        uVar1 = (uint)local_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



uint __cdecl FUN_0140bc8e(char **param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint uVar34;
  uint uVar35;
  uint uVar36;
  uint uVar37;
  uint uVar38;
  uint uVar39;
  uint uVar40;
  uint uVar41;
  uint uVar42;
  uint uVar43;
  
  uVar1 = (uint)DAT_01415c22;
  uVar43 = (uint)DAT_01415c24;
  if (param_1 == (char **)0x0) {
    uVar43 = 0xffffffff;
  }
  else {
    uVar2 = FUN_0140dec9(1,uVar1,0x31,param_1 + 1);
    uVar3 = FUN_0140dec9(1,uVar1,0x32,param_1 + 2);
    uVar4 = FUN_0140dec9(1,uVar1,0x33,param_1 + 3);
    uVar5 = FUN_0140dec9(1,uVar1,0x34,param_1 + 4);
    uVar6 = FUN_0140dec9(1,uVar1,0x35,param_1 + 5);
    uVar7 = FUN_0140dec9(1,uVar1,0x36,param_1 + 6);
    uVar8 = FUN_0140dec9(1,uVar1,0x37,param_1);
    uVar9 = FUN_0140dec9(1,uVar1,0x2a,param_1 + 8);
    uVar10 = FUN_0140dec9(1,uVar1,0x2b,param_1 + 9);
    uVar11 = FUN_0140dec9(1,uVar1,0x2c,param_1 + 10);
    uVar12 = FUN_0140dec9(1,uVar1,0x2d,param_1 + 0xb);
    uVar13 = FUN_0140dec9(1,uVar1,0x2e,param_1 + 0xc);
    uVar14 = FUN_0140dec9(1,uVar1,0x2f,param_1 + 0xd);
    uVar15 = FUN_0140dec9(1,uVar1,0x30,param_1 + 7);
    uVar16 = FUN_0140dec9(1,uVar1,0x44,param_1 + 0xe);
    uVar17 = FUN_0140dec9(1,uVar1,0x45,param_1 + 0xf);
    uVar18 = FUN_0140dec9(1,uVar1,0x46,param_1 + 0x10);
    uVar19 = FUN_0140dec9(1,uVar1,0x47,param_1 + 0x11);
    uVar20 = FUN_0140dec9(1,uVar1,0x48,param_1 + 0x12);
    uVar21 = FUN_0140dec9(1,uVar1,0x49,param_1 + 0x13);
    uVar22 = FUN_0140dec9(1,uVar1,0x4a,param_1 + 0x14);
    uVar23 = FUN_0140dec9(1,uVar1,0x4b,param_1 + 0x15);
    uVar24 = FUN_0140dec9(1,uVar1,0x4c,param_1 + 0x16);
    uVar25 = FUN_0140dec9(1,uVar1,0x4d,param_1 + 0x17);
    uVar26 = FUN_0140dec9(1,uVar1,0x4e,param_1 + 0x18);
    uVar27 = FUN_0140dec9(1,uVar1,0x4f,param_1 + 0x19);
    uVar28 = FUN_0140dec9(1,uVar1,0x38,param_1 + 0x1a);
    uVar29 = FUN_0140dec9(1,uVar1,0x39,param_1 + 0x1b);
    uVar30 = FUN_0140dec9(1,uVar1,0x3a,param_1 + 0x1c);
    uVar31 = FUN_0140dec9(1,uVar1,0x3b,param_1 + 0x1d);
    uVar32 = FUN_0140dec9(1,uVar1,0x3c,param_1 + 0x1e);
    uVar33 = FUN_0140dec9(1,uVar1,0x3d,param_1 + 0x1f);
    uVar34 = FUN_0140dec9(1,uVar1,0x3e,param_1 + 0x20);
    uVar35 = FUN_0140dec9(1,uVar1,0x3f,param_1 + 0x21);
    uVar36 = FUN_0140dec9(1,uVar1,0x40,param_1 + 0x22);
    uVar37 = FUN_0140dec9(1,uVar1,0x41,param_1 + 0x23);
    uVar38 = FUN_0140dec9(1,uVar1,0x42,param_1 + 0x24);
    uVar39 = FUN_0140dec9(1,uVar1,0x43,param_1 + 0x25);
    uVar40 = FUN_0140dec9(1,uVar1,0x28,param_1 + 0x26);
    uVar1 = FUN_0140dec9(1,uVar1,0x29,param_1 + 0x27);
    uVar41 = FUN_0140dec9(1,uVar43,0x1f,param_1 + 0x28);
    uVar42 = FUN_0140dec9(1,uVar43,0x20,param_1 + 0x29);
    uVar43 = FUN_0140dec9(1,uVar43,0x1003,param_1 + 0x2a);
    uVar43 = uVar43 | uVar2 | uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 |
                      uVar11 | uVar12 | uVar13 | uVar14 | uVar15 | uVar16 | uVar17 | uVar18 | uVar19
                      | uVar20 | uVar21 | uVar22 | uVar23 | uVar24 | uVar25 | uVar26 | uVar27 |
                      uVar28 | uVar29 | uVar30 | uVar31 | uVar32 | uVar33 | uVar34 | uVar35 | uVar36
                      | uVar37 | uVar38 | uVar39 | uVar40 | uVar1 | uVar41 | uVar42;
  }
  return uVar43;
}



void __cdecl FUN_0140bfdc(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    FUN_01404c4e((undefined *)param_1[1]);
    FUN_01404c4e((undefined *)param_1[2]);
    FUN_01404c4e((undefined *)param_1[3]);
    FUN_01404c4e((undefined *)param_1[4]);
    FUN_01404c4e((undefined *)param_1[5]);
    FUN_01404c4e((undefined *)param_1[6]);
    FUN_01404c4e((undefined *)*param_1);
    FUN_01404c4e((undefined *)param_1[8]);
    FUN_01404c4e((undefined *)param_1[9]);
    FUN_01404c4e((undefined *)param_1[10]);
    FUN_01404c4e((undefined *)param_1[0xb]);
    FUN_01404c4e((undefined *)param_1[0xc]);
    FUN_01404c4e((undefined *)param_1[0xd]);
    FUN_01404c4e((undefined *)param_1[7]);
    FUN_01404c4e((undefined *)param_1[0xe]);
    FUN_01404c4e((undefined *)param_1[0xf]);
    FUN_01404c4e((undefined *)param_1[0x10]);
    FUN_01404c4e((undefined *)param_1[0x11]);
    FUN_01404c4e((undefined *)param_1[0x12]);
    FUN_01404c4e((undefined *)param_1[0x13]);
    FUN_01404c4e((undefined *)param_1[0x14]);
    FUN_01404c4e((undefined *)param_1[0x15]);
    FUN_01404c4e((undefined *)param_1[0x16]);
    FUN_01404c4e((undefined *)param_1[0x17]);
    FUN_01404c4e((undefined *)param_1[0x18]);
    FUN_01404c4e((undefined *)param_1[0x19]);
    FUN_01404c4e((undefined *)param_1[0x1a]);
    FUN_01404c4e((undefined *)param_1[0x1b]);
    FUN_01404c4e((undefined *)param_1[0x1c]);
    FUN_01404c4e((undefined *)param_1[0x1d]);
    FUN_01404c4e((undefined *)param_1[0x1e]);
    FUN_01404c4e((undefined *)param_1[0x1f]);
    FUN_01404c4e((undefined *)param_1[0x20]);
    FUN_01404c4e((undefined *)param_1[0x21]);
    FUN_01404c4e((undefined *)param_1[0x22]);
    FUN_01404c4e((undefined *)param_1[0x23]);
    FUN_01404c4e((undefined *)param_1[0x24]);
    FUN_01404c4e((undefined *)param_1[0x25]);
    FUN_01404c4e((undefined *)param_1[0x26]);
    FUN_01404c4e((undefined *)param_1[0x27]);
    FUN_01404c4e((undefined *)param_1[0x28]);
    FUN_01404c4e((undefined *)param_1[0x29]);
    FUN_01404c4e((undefined *)param_1[0x2a]);
  }
  return;
}



void __cdecl FUN_0140c341(char *param_1)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  
  cVar2 = *param_1;
  do {
    if (cVar2 == '\0') {
      return;
    }
    if ((cVar2 < '0') || ('9' < cVar2)) {
      pcVar3 = param_1;
      if (cVar2 != ';') goto LAB_0140c358;
      do {
        pcVar1 = pcVar3 + 1;
        *pcVar3 = pcVar3[1];
        pcVar3 = pcVar1;
      } while (*pcVar1 != '\0');
    }
    else {
      *param_1 = cVar2 + -0x30;
LAB_0140c358:
      param_1 = param_1 + 1;
    }
    cVar2 = *param_1;
  } while( true );
}



uint __cdecl FUN_0140c443(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  
  uVar15 = (uint)DAT_01415c18;
  if (param_1 == 0) {
    uVar15 = 0xffffffff;
  }
  else {
    uVar1 = FUN_0140dec9(1,uVar15,0x15,(char **)(param_1 + 0xc));
    uVar2 = FUN_0140dec9(1,uVar15,0x14,(char **)(param_1 + 0x10));
    uVar3 = FUN_0140dec9(1,uVar15,0x16,(char **)(param_1 + 0x14));
    uVar4 = FUN_0140dec9(1,uVar15,0x17,(char **)(param_1 + 0x18));
    uVar5 = FUN_0140dec9(1,uVar15,0x18,(char **)(param_1 + 0x1c));
    FUN_0140c565(*(char **)(param_1 + 0x1c));
    uVar6 = FUN_0140dec9(1,uVar15,0x50,(char **)(param_1 + 0x20));
    uVar7 = FUN_0140dec9(1,uVar15,0x51,(char **)(param_1 + 0x24));
    uVar8 = FUN_0140dec9(0,uVar15,0x1a,(char **)(param_1 + 0x28));
    uVar9 = FUN_0140dec9(0,uVar15,0x19,(char **)(param_1 + 0x29));
    uVar10 = FUN_0140dec9(0,uVar15,0x54,(char **)(param_1 + 0x2a));
    uVar11 = FUN_0140dec9(0,uVar15,0x55,(char **)(param_1 + 0x2b));
    uVar12 = FUN_0140dec9(0,uVar15,0x56,(char **)(param_1 + 0x2c));
    uVar13 = FUN_0140dec9(0,uVar15,0x57,(char **)(param_1 + 0x2d));
    uVar14 = FUN_0140dec9(0,uVar15,0x52,(char **)(param_1 + 0x2e));
    uVar15 = FUN_0140dec9(0,uVar15,0x53,(char **)(param_1 + 0x2f));
    uVar15 = uVar15 | uVar1 | uVar2 | uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10
                      | uVar11 | uVar12 | uVar13 | uVar14;
  }
  return uVar15;
}



void __cdecl FUN_0140c565(char *param_1)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  
  cVar2 = *param_1;
  do {
    if (cVar2 == '\0') {
      return;
    }
    if ((cVar2 < '0') || ('9' < cVar2)) {
      pcVar3 = param_1;
      if (cVar2 != ';') goto LAB_0140c57c;
      do {
        pcVar1 = pcVar3 + 1;
        *pcVar3 = pcVar3[1];
        pcVar3 = pcVar1;
      } while (*pcVar1 != '\0');
    }
    else {
      *param_1 = cVar2 + -0x30;
LAB_0140c57c:
      param_1 = param_1 + 1;
    }
    cVar2 = *param_1;
  } while( true );
}



void __cdecl FUN_0140c59c(int param_1)

{
  if ((param_1 != 0) && (*(undefined **)(param_1 + 0xc) != &DAT_01415c54)) {
    FUN_01404c4e(*(undefined **)(param_1 + 0xc));
    FUN_01404c4e(*(undefined **)(param_1 + 0x10));
    FUN_01404c4e(*(undefined **)(param_1 + 0x14));
    FUN_01404c4e(*(undefined **)(param_1 + 0x18));
    FUN_01404c4e(*(undefined **)(param_1 + 0x1c));
    FUN_01404c4e(*(undefined **)(param_1 + 0x20));
    FUN_01404c4e(*(undefined **)(param_1 + 0x24));
  }
  return;
}



undefined4 FUN_0140c5ea(void)

{
  BYTE *pBVar1;
  undefined4 *puVar2;
  byte bVar3;
  int iVar4;
  undefined2 *puVar5;
  BOOL BVar6;
  BYTE *pBVar7;
  uint uVar8;
  LPCWSTR pWVar9;
  undefined4 uVar10;
  _cpinfo local_28;
  undefined2 *local_14;
  undefined2 *local_10;
  LPCWSTR local_c;
  LPCSTR local_8;
  
  uVar10 = 0;
  local_8 = (LPCSTR)0x0;
  local_c = (LPCWSTR)0x0;
  if (DAT_01415bc0 == 0) {
    PTR_DAT_014137b8 = &DAT_014137c2;
    PTR_DAT_014137bc = &DAT_014137c2;
    FUN_01404c4e((undefined *)DAT_01415bfc);
    FUN_01404c4e((undefined *)DAT_01415c00);
    DAT_01415bfc = (undefined2 *)0x0;
    DAT_01415c00 = (undefined2 *)0x0;
    return 0;
  }
  if ((DAT_01415bd0 != 0) ||
     (iVar4 = FUN_0140dec9(0,(uint)DAT_01415c10,0x1004,(char **)&DAT_01415bd0), iVar4 == 0)) {
    puVar5 = (undefined2 *)_malloc(0x202);
    local_14 = puVar5;
    local_10 = (undefined2 *)_malloc(0x202);
    local_8 = (LPCSTR)_malloc(0x101);
    local_c = (LPCWSTR)_malloc(0x202);
    if ((puVar5 != (undefined2 *)0x0) &&
       (((local_10 != (undefined2 *)0x0 && (local_8 != (LPCSTR)0x0)) && (local_c != (LPCWSTR)0x0))))
    {
      iVar4 = 0;
      do {
        local_8[iVar4] = (CHAR)iVar4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x100);
      BVar6 = GetCPInfo(DAT_01415bd0,&local_28);
      if ((BVar6 != 0) && (local_28.MaxCharSize < 3)) {
        DAT_014139c4 = local_28.MaxCharSize & 0xffff;
        if ((1 < DAT_014139c4) && (local_28.LeadByte[0] != '\0')) {
          pBVar7 = local_28.LeadByte + 1;
          do {
            bVar3 = *pBVar7;
            if (bVar3 == 0) break;
            for (uVar8 = (uint)pBVar7[-1]; (int)uVar8 <= (int)(uint)bVar3; uVar8 = uVar8 + 1) {
              local_8[uVar8] = '\0';
              bVar3 = *pBVar7;
            }
            pBVar1 = pBVar7 + 1;
            pBVar7 = pBVar7 + 2;
          } while (*pBVar1 != 0);
        }
        BVar6 = FUN_01408701(1,local_8,0x100,puVar5 + 1,0,0,0);
        if (BVar6 != 0) {
          *puVar5 = 0;
          iVar4 = 0;
          pWVar9 = local_c;
          do {
            *pWVar9 = (WCHAR)iVar4;
            pWVar9 = pWVar9 + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 < 0x100);
          puVar2 = (undefined4 *)(local_10 + 1);
          BVar6 = FUN_0140e007(1,local_c,0x100,puVar2,0,0);
          if (BVar6 != 0) {
            *local_10 = 0;
            if ((1 < (int)DAT_014139c4) && (local_28.LeadByte[0] != '\0')) {
              pBVar7 = local_28.LeadByte + 1;
              do {
                if (*pBVar7 == 0) break;
                uVar8 = (uint)pBVar7[-1];
                if (uVar8 <= *pBVar7) {
                  puVar5 = local_14 + uVar8 + 1;
                  do {
                    *puVar5 = 0x8000;
                    uVar8 = uVar8 + 1;
                    puVar5 = puVar5 + 1;
                  } while ((int)uVar8 <= (int)(uint)*pBVar7);
                }
                pBVar1 = pBVar7 + 1;
                pBVar7 = pBVar7 + 2;
              } while (*pBVar1 != 0);
            }
            PTR_DAT_014137b8 = (undefined *)(local_14 + 1);
            PTR_DAT_014137bc = (undefined *)puVar2;
            if (DAT_01415bfc != (undefined2 *)0x0) {
              FUN_01404c4e((undefined *)DAT_01415bfc);
            }
            DAT_01415bfc = local_14;
            if (DAT_01415c00 != (undefined2 *)0x0) {
              FUN_01404c4e((undefined *)DAT_01415c00);
            }
            DAT_01415c00 = local_10;
            goto LAB_0140c7c8;
          }
        }
      }
    }
  }
  FUN_01404c4e((undefined *)local_14);
  FUN_01404c4e((undefined *)local_10);
  uVar10 = 1;
LAB_0140c7c8:
  FUN_01404c4e(local_8);
  FUN_01404c4e((undefined *)local_c);
  return uVar10;
}



int __cdecl FUN_0140c840(byte *param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *param_2;
    if (bVar1 == 0) break;
    param_2 = param_2 + 1;
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  iVar3 = -1;
  do {
    iVar3 = iVar3 + 1;
    bVar1 = *param_1;
    if (bVar1 == 0) {
      return iVar3;
    }
    param_1 = param_1 + 1;
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return iVar3;
}



undefined4 __thiscall FUN_0140c87e(void *this,char *param_1,undefined2 *param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  BOOL BVar3;
  void *extraout_ECX;
  void *extraout_ECX_00;
  
  if (DAT_01415c48 == (code *)0x0) {
    iVar1 = FUN_0140cfaf();
    this = extraout_ECX;
    if (iVar1 == 0) {
      DAT_01415c48 = FUN_0140cfe5;
    }
    else {
      DAT_01415c48 = GetLocaleInfoA_exref;
    }
  }
  if (param_1 != (char *)0x0) {
    DAT_01415c38 = param_1;
    if (*param_1 != '\0') {
      FUN_0140c9fb(this,0x1414840,0x40,(byte **)&DAT_01415c38);
      this = extraout_ECX_00;
    }
    DAT_01415c3c = param_1 + 0x40;
    if ((DAT_01415c3c != (char *)0x0) && (*DAT_01415c3c != '\0')) {
      FUN_0140c9fb(this,0x1414788,0x16,(byte **)&DAT_01415c3c);
    }
    DAT_01415c40 = 0;
    if ((DAT_01415c38 != (char *)0x0) && (*DAT_01415c38 != '\0')) {
      if ((DAT_01415c3c == (char *)0x0) || (*DAT_01415c3c == '\0')) {
        FUN_0140ccde();
      }
      else {
        FUN_0140ca53();
      }
      goto LAB_0140c93b;
    }
    if ((DAT_01415c3c != (char *)0x0) && (*DAT_01415c3c != '\0')) {
      FUN_0140cdf1();
      goto LAB_0140c93b;
    }
  }
  FUN_0140ceae();
LAB_0140c93b:
  if ((((DAT_01415c40 == 0) || (uVar2 = FUN_0140cec8((byte *)(param_1 + 0x80)), uVar2 == 0)) ||
      (BVar3 = IsValidCodePage(uVar2 & 0xffff), BVar3 == 0)) ||
     (BVar3 = IsValidLocale(DAT_01415c28,1), BVar3 == 0)) {
    return 0;
  }
  if (param_2 != (undefined2 *)0x0) {
    *param_2 = (undefined2)DAT_01415c28;
    param_2[1] = (undefined2)DAT_01415c44;
    param_2[2] = (short)uVar2;
  }
  if (param_3 != 0) {
    iVar1 = (*DAT_01415c48)(DAT_01415c28,0x1001,param_3,0x40);
    if (iVar1 == 0) {
      return 0;
    }
    iVar1 = (*DAT_01415c48)(DAT_01415c44,0x1002,param_3 + 0x40,0x40);
    if (iVar1 == 0) {
      return 0;
    }
    FUN_0140e1cc(uVar2,(char *)(param_3 + 0x80),10);
  }
  return 1;
}



void __thiscall FUN_0140c9fb(void *this,int param_1,int param_2,byte **param_3)

{
  byte **ppbVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  uVar2 = 1;
  if (-1 < param_2) {
    do {
      if (uVar2 == 0) {
        return;
      }
      iVar4 = (param_2 + iVar3) / 2;
      ppbVar1 = *(byte ***)(param_1 + iVar4 * 8);
      uVar2 = FUN_0140a6c0(this,*param_3,(byte *)ppbVar1);
      this = ppbVar1;
      if (uVar2 == 0) {
        *param_3 = (byte *)(param_1 + iVar4 * 8 + 4);
        this = param_3;
      }
      else if ((int)uVar2 < 0) {
        param_2 = iVar4 + -1;
      }
      else {
        iVar3 = iVar4 + 1;
      }
    } while (iVar3 <= param_2);
  }
  return;
}



void FUN_0140ca53(void)

{
  size_t sVar1;
  
  sVar1 = _strlen(DAT_01415c38);
  DAT_01415c34 = (uint)(sVar1 == 3);
  sVar1 = _strlen(DAT_01415c3c);
  DAT_01415c2c = (uint)(sVar1 == 3);
  DAT_01415c28 = 0;
  if (DAT_01415c34 == 0) {
    DAT_01415c30 = FUN_0140d104(DAT_01415c38);
  }
  else {
    DAT_01415c30 = 2;
  }
  EnumSystemLocalesA(FUN_0140cada,1);
  if ((((DAT_01415c40 & 0x100) == 0) || ((DAT_01415c40 & 0x200) == 0)) || ((DAT_01415c40 & 7) == 0))
  {
    DAT_01415c40 = 0;
  }
  return;
}



uint FUN_0140cada(char *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  void *pvVar4;
  void *this;
  void *this_00;
  void *this_01;
  byte local_7c [120];
  
  iVar1 = FUN_0140d0cb(param_1);
  iVar2 = (*DAT_01415c48)(iVar1,(-(uint)(DAT_01415c2c != 0) & 0xfffff005) + 0x1002,local_7c,0x78);
  if (iVar2 == 0) {
    DAT_01415c40 = 0;
    return 1;
  }
  uVar3 = FUN_0140a6c0(this,DAT_01415c3c,local_7c);
  if (uVar3 == 0) {
    iVar2 = (*DAT_01415c48)(iVar1,(-(uint)(DAT_01415c34 != 0) & 0xfffff002) + 0x1001,local_7c,0x78);
    if (iVar2 == 0) {
      DAT_01415c40 = 0;
      return 1;
    }
    uVar3 = FUN_0140a6c0(this_00,DAT_01415c38,local_7c);
    if (uVar3 == 0) {
      DAT_01415c40 = DAT_01415c40 | 0x304;
      DAT_01415c44 = iVar1;
LAB_0140cb80:
      DAT_01415c28 = iVar1;
    }
    else if ((DAT_01415c40 & 2) == 0) {
      if ((DAT_01415c30 == (void *)0x0) ||
         (pvVar4 = FUN_0140e370(DAT_01415c38,(char *)local_7c,DAT_01415c30), pvVar4 != (void *)0x0))
      {
        if (((DAT_01415c40 & 1) == 0) && (iVar2 = FUN_0140cf2e((short)iVar1), iVar2 != 0)) {
          DAT_01415c40 = DAT_01415c40 | 1;
          DAT_01415c44 = iVar1;
        }
      }
      else {
        DAT_01415c40 = DAT_01415c40 | 2;
        DAT_01415c44 = iVar1;
        pvVar4 = (void *)_strlen((char *)DAT_01415c38);
        if (pvVar4 == DAT_01415c30) goto LAB_0140cb80;
      }
    }
  }
  if ((DAT_01415c40 & 0x300) == 0x300) goto LAB_0140ccca;
  iVar2 = (*DAT_01415c48)(iVar1,(-(uint)(DAT_01415c34 != 0) & 0xfffff002) + 0x1001,local_7c,0x78);
  if (iVar2 == 0) {
    DAT_01415c40 = 0;
    return 1;
  }
  uVar3 = FUN_0140a6c0(this_01,DAT_01415c38,local_7c);
  if (uVar3 == 0) {
    DAT_01415c40 = DAT_01415c40 | 0x200;
    if (((DAT_01415c34 == 0) && (DAT_01415c30 != (void *)0x0)) &&
       (pvVar4 = (void *)_strlen((char *)DAT_01415c38), pvVar4 == DAT_01415c30)) {
      iVar2 = 1;
      goto LAB_0140cca9;
    }
  }
  else {
    if (((DAT_01415c34 != 0) || (DAT_01415c30 == (void *)0x0)) ||
       (pvVar4 = FUN_0140e370(DAT_01415c38,(char *)local_7c,DAT_01415c30), pvVar4 != (void *)0x0))
    goto LAB_0140ccca;
    iVar2 = 0;
LAB_0140cca9:
    iVar2 = FUN_0140cf4d(iVar1,iVar2);
    if (iVar2 == 0) goto LAB_0140ccca;
  }
  DAT_01415c40 = DAT_01415c40 | 0x100;
  if (DAT_01415c28 == 0) {
    DAT_01415c28 = iVar1;
  }
LAB_0140ccca:
  return ~DAT_01415c40 >> 2 & 1;
}



void FUN_0140ccde(void)

{
  size_t sVar1;
  
  sVar1 = _strlen(DAT_01415c38);
  DAT_01415c34 = (uint)(sVar1 == 3);
  if (sVar1 == 3) {
    DAT_01415c30 = 2;
  }
  else {
    DAT_01415c30 = FUN_0140d104(DAT_01415c38);
  }
  EnumSystemLocalesA(FUN_0140cd34,1);
  if ((DAT_01415c40 & 4) == 0) {
    DAT_01415c40 = 0;
  }
  return;
}



uint FUN_0140cd34(char *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  void *pvVar4;
  void *this;
  byte local_7c [120];
  
  iVar1 = FUN_0140d0cb(param_1);
  iVar2 = (*DAT_01415c48)(iVar1,(-(uint)(DAT_01415c34 != 0) & 0xfffff002) + 0x1001,local_7c,0x78);
  if (iVar2 == 0) {
    DAT_01415c40 = 0;
    return 1;
  }
  uVar3 = FUN_0140a6c0(this,DAT_01415c38,local_7c);
  if (uVar3 == 0) {
    if (DAT_01415c34 == 0) {
      iVar2 = 1;
      goto LAB_0140cdc0;
    }
  }
  else {
    if (((DAT_01415c34 != 0) || (DAT_01415c30 == (void *)0x0)) ||
       (pvVar4 = FUN_0140e370(DAT_01415c38,(char *)local_7c,DAT_01415c30), pvVar4 != (void *)0x0))
    goto LAB_0140cddf;
    iVar2 = 0;
LAB_0140cdc0:
    iVar2 = FUN_0140cf4d(iVar1,iVar2);
    if (iVar2 == 0) goto LAB_0140cddf;
  }
  DAT_01415c40 = DAT_01415c40 | 4;
  DAT_01415c28 = iVar1;
  DAT_01415c44 = iVar1;
LAB_0140cddf:
  return ~DAT_01415c40 >> 2 & 1;
}



void FUN_0140cdf1(void)

{
  size_t sVar1;
  
  sVar1 = _strlen(DAT_01415c3c);
  DAT_01415c2c = (uint)(sVar1 == 3);
  EnumSystemLocalesA(FUN_0140ce28,1);
  if ((DAT_01415c40 & 4) == 0) {
    DAT_01415c40 = 0;
  }
  return;
}



uint FUN_0140ce28(char *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  void *this;
  byte local_7c [120];
  
  iVar1 = FUN_0140d0cb(param_1);
  iVar2 = (*DAT_01415c48)(iVar1,(-(uint)(DAT_01415c2c != 0) & 0xfffff005) + 0x1002,local_7c,0x78);
  if (iVar2 == 0) {
    DAT_01415c40 = 0;
    uVar3 = 1;
  }
  else {
    uVar3 = FUN_0140a6c0(this,DAT_01415c3c,local_7c);
    if (uVar3 == 0) {
      iVar2 = FUN_0140cf2e((short)iVar1);
      if (iVar2 != 0) {
        DAT_01415c40 = DAT_01415c40 | 4;
        DAT_01415c28 = iVar1;
        DAT_01415c44 = iVar1;
      }
    }
    uVar3 = ~DAT_01415c40 >> 2 & 1;
  }
  return uVar3;
}



void FUN_0140ceae(void)

{
  DAT_01415c40._0_2_ = (ushort)DAT_01415c40 | 0x104;
  DAT_01415c44 = GetUserDefaultLCID();
  DAT_01415c28 = DAT_01415c44;
  return;
}



void __cdecl FUN_0140cec8(byte *param_1)

{
  int iVar1;
  undefined *extraout_ECX;
  undefined4 uVar2;
  undefined *this;
  byte local_c [8];
  
  if (((param_1 == (byte *)0x0) || (*param_1 == 0)) ||
     (iVar1 = _strcmp((char *)param_1,"ACP"), iVar1 == 0)) {
    uVar2 = 0x1004;
  }
  else {
    this = &DAT_0140fdec;
    iVar1 = _strcmp((char *)param_1,"OCP");
    if (iVar1 != 0) goto LAB_0140cf24;
    uVar2 = 0xb;
  }
  iVar1 = (*DAT_01415c48)(DAT_01415c44,uVar2,local_c,8);
  if (iVar1 == 0) {
    return;
  }
  param_1 = local_c;
  this = extraout_ECX;
LAB_0140cf24:
  FUN_0140b8cd(this,param_1);
  return;
}



undefined4 __cdecl FUN_0140cf2e(short param_1)

{
  short *psVar1;
  
  psVar1 = &DAT_01414774;
  do {
    if (param_1 == *psVar1) {
      return 0;
    }
    psVar1 = psVar1 + 1;
  } while ((int)psVar1 < 0x1414788);
  return 1;
}



undefined4 __cdecl FUN_0140cf4d(int param_1,int param_2)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  char local_7c [120];
  
  iVar1 = (*DAT_01415c48)((ushort)param_1 & 0x3ff | 0x400,1,local_7c,0x78);
  if (iVar1 == 0) {
    return 0;
  }
  iVar1 = FUN_0140d0cb(local_7c);
  if ((param_1 != iVar1) && (param_2 != 0)) {
    sVar2 = FUN_0140d104(DAT_01415c38);
    sVar3 = _strlen(DAT_01415c38);
    if (sVar2 == sVar3) {
      return 0;
    }
  }
  return 1;
}



undefined4 FUN_0140cfaf(void)

{
  BOOL BVar1;
  _OSVERSIONINFOA local_98;
  
  local_98.dwOSVersionInfoSize = 0x94;
  BVar1 = GetVersionExA(&local_98);
  if ((BVar1 != 0) && (local_98.dwPlatformId == 2)) {
    return 1;
  }
  return 0;
}



int FUN_0140cfe5(uint param_1,LCTYPE param_2,char *param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  char *_Source;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar4 = 0x1a;
  do {
    iVar2 = (iVar4 + iVar3) / 2;
    uVar1 = *(uint *)(iVar2 * 0x2c + 0x14142d0);
    if (param_1 == uVar1) {
      if (param_2 == 1) {
        _Source = &DAT_014142d4 + iVar2 * 0x2c;
      }
      else if (param_2 == 3) {
        _Source = &DAT_014142e0 + iVar2 * 0x2c;
      }
      else if (param_2 == 7) {
        _Source = &DAT_014142e8 + iVar2 * 0x2c;
      }
      else if (param_2 == 0xb) {
        _Source = &DAT_014142ec + iVar2 * 0x2c;
      }
      else if (param_2 == 0x1001) {
        _Source = *(char **)(iVar2 * 0x2c + 0x14142dc);
      }
      else if (param_2 == 0x1002) {
        _Source = *(char **)(iVar2 * 0x2c + 0x14142e4);
      }
      else {
        if (param_2 != 0x1004) break;
        _Source = &DAT_014142f4 + iVar2 * 0x2c;
      }
      if ((_Source != (char *)0x0) && (0 < param_4)) {
        _strncpy(param_3,_Source,param_4 - 1);
        param_3[param_4 + -1] = '\0';
        return 1;
      }
      break;
    }
    if (param_1 < uVar1) {
      iVar4 = iVar2 + -1;
    }
    else {
      iVar3 = iVar2 + 1;
    }
  } while (iVar3 <= iVar4);
  iVar4 = GetLocaleInfoA(param_1,param_2,param_3,param_4);
  return iVar4;
}



int __cdecl FUN_0140d0cb(char *param_1)

{
  int iVar1;
  char cVar2;
  
  iVar1 = 0;
  while( true ) {
    cVar2 = *param_1;
    param_1 = param_1 + 1;
    if (cVar2 == '\0') break;
    if ((cVar2 < 'a') || ('f' < cVar2)) {
      if (('@' < cVar2) && (cVar2 < 'G')) {
        cVar2 = cVar2 + -7;
      }
    }
    else {
      cVar2 = cVar2 + -0x27;
    }
    iVar1 = (iVar1 + 0xffffffd) * 0x10 + (int)cVar2;
  }
  return iVar1;
}



int __cdecl FUN_0140d104(char *param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  while( true ) {
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if (((cVar1 < 'A') || ('Z' < cVar1)) && ((cVar1 < 'a' || ('z' < cVar1)))) break;
    iVar2 = iVar2 + 1;
  }
  return iVar2;
}



int __cdecl FUN_0140d125(uint param_1,int param_2)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_01415fc0) &&
     ((*(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01408d0f(param_1);
    iVar1 = FUN_0140d17e(param_1,param_2);
    FUN_01408d6e(param_1);
    return iVar1;
  }
  pDVar2 = FUN_01406c66();
  *pDVar2 = 9;
  return -1;
}



int __cdecl FUN_0140d17e(uint param_1,int param_2)

{
  byte bVar1;
  DWORD *pDVar2;
  byte bVar3;
  
  bVar1 = *(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24);
  if (param_2 == 0x8000) {
    bVar3 = bVar1 & 0x7f;
  }
  else {
    if (param_2 != 0x4000) {
      pDVar2 = FUN_01406c66();
      *pDVar2 = 0x16;
      return -1;
    }
    bVar3 = bVar1 | 0x80;
  }
  *(byte *)((&DAT_01415ec0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) = bVar3;
  return (-(uint)((bVar1 & 0x80) != 0) & 0xffffc000) + 0x8000;
}



// Library Function - Single Match
//  __mbsnbicoll
// 
// Library: Visual Studio 2003 Release

int __cdecl __mbsnbicoll(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  if (_MaxCount == 0) {
    return 0;
  }
  iVar1 = FUN_0140e471(DAT_01415ea4,1,_Str1,_MaxCount,_Str2,_MaxCount,DAT_01415c78);
  if (iVar1 == 0) {
    return 0x7fffffff;
  }
  return iVar1 + -2;
}



undefined4 FUN_0140d253(void)

{
  LPCWSTR lpWideCharStr;
  size_t mem_Size;
  uint *lpMultiByteStr;
  int iVar1;
  LPCWSTR *ppWVar2;
  
  lpWideCharStr = *DAT_01415944;
  ppWVar2 = DAT_01415944;
  while( true ) {
    if (lpWideCharStr == (LPCWSTR)0x0) {
      return 0;
    }
    mem_Size = WideCharToMultiByte(1,0,lpWideCharStr,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    if (((mem_Size == 0) ||
        (lpMultiByteStr = (uint *)_malloc(mem_Size), lpMultiByteStr == (uint *)0x0)) ||
       (iVar1 = WideCharToMultiByte(1,0,*ppWVar2,-1,(LPSTR)lpMultiByteStr,mem_Size,(LPCSTR)0x0,
                                    (LPBOOL)0x0), iVar1 == 0)) break;
    FUN_0140e719(lpMultiByteStr,0);
    lpWideCharStr = ppWVar2[1];
    ppWVar2 = ppWVar2 + 1;
  }
  return 0xffffffff;
}



undefined * FUN_0140d2c1(void)

{
  size_t sVar1;
  size_t sVar2;
  undefined *puVar3;
  uint *puVar4;
  int iVar5;
  char **ppcVar6;
  undefined *puVar7;
  uint *puVar8;
  uint **ppuVar9;
  int local_8;
  
  ppuVar9 = (uint **)PTR_PTR_DAT_01414a50;
  iVar5 = 0;
  local_8 = 7;
  ppcVar6 = (char **)PTR_PTR_DAT_01414a50;
  do {
    sVar1 = _strlen(ppcVar6[7]);
    sVar2 = _strlen(*ppcVar6);
    ppcVar6 = ppcVar6 + 1;
    local_8 = local_8 + -1;
    iVar5 = sVar2 + iVar5 + 2 + sVar1;
  } while (local_8 != 0);
  puVar3 = (undefined *)_malloc(iVar5 + 1);
  if (puVar3 != (undefined *)0x0) {
    iVar5 = 7;
    puVar7 = puVar3;
    do {
      *puVar7 = 0x3a;
      puVar4 = FUN_014028f0((uint *)(puVar7 + 1),*ppuVar9);
      sVar1 = _strlen((char *)puVar4);
      puVar7 = (undefined *)((int)(puVar7 + 1) + sVar1);
      *puVar7 = 0x3a;
      puVar8 = (uint *)(puVar7 + 1);
      puVar4 = FUN_014028f0(puVar8,ppuVar9[7]);
      sVar1 = _strlen((char *)puVar4);
      puVar7 = (undefined *)((int)puVar8 + sVar1);
      ppuVar9 = ppuVar9 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    *puVar7 = 0;
  }
  return puVar3;
}



undefined * FUN_0140d350(void)

{
  size_t sVar1;
  size_t sVar2;
  undefined *puVar3;
  uint *puVar4;
  int iVar5;
  char **ppcVar6;
  undefined *puVar7;
  uint *puVar8;
  uint **ppuVar9;
  int local_c;
  int local_8;
  
  puVar7 = PTR_PTR_DAT_01414a50;
  local_8 = 0;
  local_c = 0xc;
  ppcVar6 = (char **)(PTR_PTR_DAT_01414a50 + 0x38);
  do {
    sVar1 = _strlen(ppcVar6[0xc]);
    sVar2 = _strlen(*ppcVar6);
    ppcVar6 = ppcVar6 + 1;
    local_c = local_c + -1;
    local_8 = sVar2 + local_8 + 2 + sVar1;
  } while (local_c != 0);
  puVar3 = (undefined *)_malloc(local_8 + 1);
  if (puVar3 != (undefined *)0x0) {
    ppuVar9 = (uint **)(puVar7 + 0x68);
    iVar5 = 0xc;
    puVar7 = puVar3;
    do {
      *puVar7 = 0x3a;
      puVar4 = FUN_014028f0((uint *)(puVar7 + 1),ppuVar9[-0xc]);
      sVar1 = _strlen((char *)puVar4);
      puVar7 = (undefined *)((int)(puVar7 + 1) + sVar1);
      *puVar7 = 0x3a;
      puVar8 = (uint *)(puVar7 + 1);
      puVar4 = FUN_014028f0(puVar8,*ppuVar9);
      sVar1 = _strlen((char *)puVar4);
      puVar7 = (undefined *)((int)puVar8 + sVar1);
      ppuVar9 = ppuVar9 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    *puVar7 = 0;
  }
  return puVar3;
}



uint ** FUN_0140d3e5(void)

{
  undefined *puVar1;
  size_t sVar2;
  size_t sVar3;
  size_t sVar4;
  size_t sVar5;
  size_t sVar6;
  uint **ppuVar7;
  uint *puVar8;
  uint *puVar9;
  uint **ppuVar10;
  int iVar11;
  uint **ppuVar12;
  int local_14;
  uint **local_10;
  char **local_c;
  uint **local_8;
  
  puVar1 = PTR_PTR_DAT_01414a50;
  iVar11 = 0;
  local_c = (char **)PTR_PTR_DAT_01414a50;
  local_10 = (uint **)0x7;
  do {
    sVar2 = _strlen(local_c[7]);
    sVar3 = _strlen(*local_c);
    local_c = local_c + 1;
    local_10 = (uint **)((int)local_10 + -1);
    iVar11 = sVar3 + iVar11 + 2 + sVar2;
  } while (local_10 != (uint **)0x0);
  local_c = (char **)(puVar1 + 0x38);
  local_10 = (uint **)0xc;
  do {
    sVar2 = _strlen(local_c[0xc]);
    sVar3 = _strlen(*local_c);
    local_c = local_c + 1;
    local_10 = (uint **)((int)local_10 + -1);
    iVar11 = sVar3 + iVar11 + 2 + sVar2;
  } while (local_10 != (uint **)0x0);
  sVar2 = _strlen(*(char **)(puVar1 + 0x98));
  sVar3 = _strlen(*(char **)(puVar1 + 0x9c));
  sVar4 = _strlen(*(char **)(puVar1 + 0xa0));
  sVar5 = _strlen(*(char **)(puVar1 + 0xa4));
  sVar6 = _strlen(*(char **)(puVar1 + 0xa8));
  ppuVar7 = (uint **)_malloc(sVar3 + iVar11 + sVar2 + sVar4 + sVar5 + sVar6 + 0xb1);
  if (ppuVar7 != (uint **)0x0) {
    ppuVar12 = ppuVar7 + 0x2b;
    FUN_01402ad0(ppuVar7,(undefined4 *)PTR_PTR_DAT_01414a50,0xac);
    local_8 = (uint **)(puVar1 + 0x1c);
    local_14 = 7;
    local_10 = ppuVar7;
    do {
      *local_10 = (uint *)ppuVar12;
      puVar8 = FUN_014028f0((uint *)ppuVar12,local_8[-7]);
      sVar2 = _strlen((char *)puVar8);
      puVar8 = (uint *)((int)ppuVar12 + sVar2 + 1);
      *(uint **)(((int)ppuVar7 - (int)puVar1) + (int)local_8) = puVar8;
      puVar9 = FUN_014028f0(puVar8,*local_8);
      sVar2 = _strlen((char *)puVar9);
      local_10 = local_10 + 1;
      local_8 = local_8 + 1;
      local_14 = local_14 + -1;
      ppuVar12 = (uint **)((int)puVar8 + sVar2 + 1);
    } while (local_14 != 0);
    local_10 = ppuVar7 + 0x1a;
    local_14 = 0xc;
    ppuVar10 = (uint **)(puVar1 + 0x38);
    do {
      *(uint ***)((int)ppuVar10 + ((int)ppuVar7 - (int)puVar1)) = ppuVar12;
      puVar8 = FUN_014028f0((uint *)ppuVar12,*ppuVar10);
      sVar2 = _strlen((char *)puVar8);
      puVar8 = (uint *)((int)ppuVar12 + sVar2 + 1);
      *local_10 = puVar8;
      puVar9 = FUN_014028f0(puVar8,ppuVar10[0xc]);
      sVar2 = _strlen((char *)puVar9);
      ppuVar10 = ppuVar10 + 1;
      local_10 = local_10 + 1;
      local_14 = local_14 + -1;
      ppuVar12 = (uint **)((int)puVar8 + sVar2 + 1);
    } while (local_14 != 0);
    ppuVar7[0x26] = (uint *)ppuVar12;
    puVar8 = FUN_014028f0((uint *)ppuVar12,*(uint **)(puVar1 + 0x98));
    sVar2 = _strlen((char *)puVar8);
    puVar8 = (uint *)((int)ppuVar12 + sVar2 + 1);
    ppuVar7[0x27] = puVar8;
    puVar9 = FUN_014028f0(puVar8,*(uint **)(puVar1 + 0x9c));
    sVar2 = _strlen((char *)puVar9);
    puVar8 = (uint *)((int)puVar8 + sVar2 + 1);
    ppuVar7[0x28] = puVar8;
    puVar9 = FUN_014028f0(puVar8,*(uint **)(puVar1 + 0xa0));
    sVar2 = _strlen((char *)puVar9);
    puVar8 = (uint *)((int)puVar8 + sVar2 + 1);
    ppuVar7[0x29] = puVar8;
    puVar9 = FUN_014028f0(puVar8,*(uint **)(puVar1 + 0xa4));
    sVar2 = _strlen((char *)puVar9);
    ppuVar7[0x2a] = (uint *)(sVar2 + 1 + (int)puVar8);
  }
  return ppuVar7;
}



int __cdecl FUN_0140d632(byte *param_1,uint param_2,byte *param_3,int *param_4,undefined *param_5)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  bool bVar4;
  uint local_8;
  
  local_8 = param_2;
  InterlockedIncrement(&DAT_01415c74);
  bVar4 = DAT_01415c70 == 0;
  if (!bVar4) {
    InterlockedDecrement(&DAT_01415c74);
    critical_code_area_executor(0x13);
  }
  pbVar2 = param_3;
  if (param_5 == (undefined *)0x0) {
    param_5 = PTR_PTR_DAT_01414a50;
  }
  while ((local_8 != 0 && (bVar1 = *pbVar2, bVar1 != 0))) {
    if (bVar1 == 0x25) {
      pbVar3 = pbVar2 + 1;
      bVar1 = *pbVar3;
      if (bVar1 == 0x23) {
        pbVar3 = pbVar2 + 2;
      }
      DAT_01415c68 = (uint)(bVar1 == 0x23);
      FUN_0140d72c(*pbVar3,param_4,&param_1,&local_8,(int)param_5);
    }
    else {
      if (((PTR_DAT_014137b8[(uint)bVar1 * 2 + 1] & 0x80) != 0) && (1 < local_8)) {
        *param_1 = bVar1;
        param_1 = param_1 + 1;
        pbVar2 = pbVar2 + 1;
        local_8 = local_8 - 1;
      }
      *param_1 = *pbVar2;
      param_1 = param_1 + 1;
      local_8 = local_8 - 1;
      pbVar3 = pbVar2;
    }
    pbVar2 = pbVar3 + 1;
  }
  if (bVar4) {
    InterlockedDecrement(&DAT_01415c74);
  }
  else {
    endCriticalFromID(0x13);
  }
  if (local_8 == 0) {
    return 0;
  }
  *param_1 = 0;
  return param_2 - local_8;
}



void __cdecl FUN_0140d72c(char param_1,int *param_2,byte **param_3,uint *param_4,int param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  uint uVar5;
  char *pcVar6;
  
  if (param_1 < '[') {
    if (param_1 != 'Z') {
      if ('M' < param_1) {
        if (param_1 == 'S') {
          uVar5 = 2;
          iVar2 = *param_2;
        }
        else {
          if (param_1 == 'U') {
            iVar3 = param_2[6];
          }
          else {
            if (param_1 != 'W') {
              if (param_1 == 'X') {
                DAT_01415c68 = 0;
                pbVar4 = *(byte **)(param_5 + 0xa8);
                goto LAB_0140dab2;
              }
              if (param_1 != 'Y') {
                return;
              }
              uVar5 = 4;
              iVar2 = (param_2[5] / 100 + 0x13) * 100 + param_2[5] % 100;
              goto LAB_0140d868;
            }
            if (param_2[6] == 0) {
              iVar3 = 6;
            }
            else {
              iVar3 = param_2[6] + -1;
            }
          }
          iVar1 = param_2[7];
          if (iVar1 < iVar3) {
            iVar2 = 0;
          }
          else {
            iVar2 = iVar1 / 7;
            if (iVar3 <= iVar1 % 7) {
              iVar2 = iVar2 + 1;
            }
          }
          uVar5 = 2;
        }
        goto LAB_0140d868;
      }
      if (param_1 == 'M') {
        uVar5 = 2;
        iVar2 = param_2[1];
        goto LAB_0140d868;
      }
      if (param_1 == '%') {
        **param_3 = 0x25;
        *param_3 = *param_3 + 1;
        *param_4 = *param_4 - 1;
        return;
      }
      if (param_1 == 'A') {
        pcVar6 = *(char **)(param_5 + 0x1c + param_2[6] * 4);
        goto LAB_0140db0e;
      }
      if (param_1 == 'B') {
        pcVar6 = *(char **)(param_5 + 0x68 + param_2[4] * 4);
        goto LAB_0140db0e;
      }
      if (param_1 == 'H') {
        uVar5 = 2;
        iVar2 = param_2[2];
        goto LAB_0140d868;
      }
      if (param_1 != 'I') {
        return;
      }
      iVar2 = param_2[2] % 0xc;
      if (iVar2 == 0) {
        iVar2 = 0xc;
      }
LAB_0140d795:
      uVar5 = 2;
LAB_0140d868:
      DAT_01415c6c = DAT_01415c68;
      FUN_0140db42(iVar2,uVar5,(char **)param_3,param_4);
      return;
    }
  }
  else {
    if (param_1 < 'n') {
      if (param_1 == 'm') {
        iVar2 = param_2[4];
        uVar5 = 2;
      }
      else {
        if (param_1 == 'a') {
          pcVar6 = *(char **)(param_5 + param_2[6] * 4);
          goto LAB_0140db0e;
        }
        if (param_1 == 'b') {
          pcVar6 = *(char **)(param_5 + 0x38 + param_2[4] * 4);
          goto LAB_0140db0e;
        }
        if (param_1 == 'c') {
          if (DAT_01415c68 == 0) {
            pbVar4 = *(byte **)(param_5 + 0xa0);
          }
          else {
            DAT_01415c68 = 0;
            pbVar4 = *(byte **)(param_5 + 0xa4);
          }
          FUN_0140dbfa(pbVar4,(int)param_2,param_3,param_4,param_5);
          if (*param_4 == 0) {
            return;
          }
          **param_3 = 0x20;
          *param_3 = *param_3 + 1;
          *param_4 = *param_4 - 1;
          pbVar4 = *(byte **)(param_5 + 0xa8);
          goto LAB_0140dab2;
        }
        if (param_1 == 'd') {
          uVar5 = 2;
          iVar2 = param_2[3];
          goto LAB_0140d868;
        }
        if (param_1 != 'j') {
          return;
        }
        iVar2 = param_2[7];
        uVar5 = 3;
      }
      iVar2 = iVar2 + 1;
      goto LAB_0140d868;
    }
    if (param_1 == 'p') {
      if (param_2[2] < 0xc) {
        pcVar6 = *(char **)(param_5 + 0x98);
      }
      else {
        pcVar6 = *(char **)(param_5 + 0x9c);
      }
      goto LAB_0140db0e;
    }
    if (param_1 == 'w') {
      uVar5 = 1;
      iVar2 = param_2[6];
      goto LAB_0140d868;
    }
    if (param_1 == 'x') {
      if (DAT_01415c68 == 0) {
        pbVar4 = *(byte **)(param_5 + 0xa0);
      }
      else {
        DAT_01415c68 = 0;
        pbVar4 = *(byte **)(param_5 + 0xa4);
      }
LAB_0140dab2:
      FUN_0140dbfa(pbVar4,(int)param_2,param_3,param_4,param_5);
      return;
    }
    if (param_1 == 'y') {
      iVar2 = param_2[5] % 100;
      goto LAB_0140d795;
    }
    if (param_1 != 'z') {
      return;
    }
  }
  InitializeCriticalSection();
  pcVar6 = (&PTR_DAT_01413fdc)[param_2[8] != 0];
LAB_0140db0e:
  FUN_0140db1b(pcVar6,(char **)param_3,(int *)param_4);
  return;
}



void __cdecl FUN_0140db1b(char *param_1,char **param_2,int *param_3)

{
  int iVar1;
  
  iVar1 = *param_3;
  for (; (iVar1 != 0 && (*param_1 != '\0')); param_1 = param_1 + 1) {
    **param_2 = *param_1;
    *param_2 = *param_2 + 1;
    *param_3 = *param_3 + -1;
    iVar1 = *param_3;
  }
  return;
}



void __cdecl FUN_0140db42(int param_1,uint param_2,char **param_3,uint *param_4)

{
  int iVar1;
  int local_8;
  
  local_8 = 0;
  if (DAT_01415c6c == 0) {
    if (param_2 < *param_4) {
      iVar1 = param_2 - 1;
      if (param_2 != 0) {
        do {
          (*param_3)[iVar1] = (char)(param_1 % 10) + '0';
          param_1 = param_1 / 10;
          local_8 = local_8 + 1;
          iVar1 = iVar1 + -1;
        } while (iVar1 != -1);
      }
      *param_3 = *param_3 + local_8;
      *param_4 = *param_4 - local_8;
    }
    else {
      *param_4 = 0;
    }
  }
  else {
    FUN_0140dbb1(param_1,param_3,param_4);
  }
  return;
}



void __cdecl FUN_0140dbb1(int param_1,char **param_2,uint *param_3)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  
  pcVar3 = *param_2;
  do {
    if (*param_3 < 2) break;
    *pcVar3 = (char)(param_1 % 10) + '0';
    pcVar3 = pcVar3 + 1;
    param_1 = param_1 / 10;
    *param_3 = *param_3 - 1;
  } while (0 < param_1);
  pcVar2 = *param_2;
  *param_2 = pcVar3;
  pcVar3 = pcVar3 + -1;
  do {
    cVar1 = *pcVar3;
    *pcVar3 = *pcVar2;
    pcVar3 = pcVar3 + -1;
    *pcVar2 = cVar1;
    pcVar2 = pcVar2 + 1;
  } while (pcVar2 < pcVar3);
  return;
}



void __cdecl FUN_0140dbfa(byte *param_1,int param_2,byte **param_3,uint *param_4,int param_5)

{
  byte bVar1;
  byte **ppbVar2;
  uint *puVar3;
  byte **ppbVar4;
  uint uVar5;
  byte *pbVar6;
  void *pvVar7;
  void *this;
  char *this_00;
  
  puVar3 = param_4;
  ppbVar2 = param_3;
  bVar1 = *param_1;
  do {
    if ((bVar1 == 0) || (*puVar3 == 0)) {
      return;
    }
    DAT_01415c6c = 0;
    bVar1 = *param_1;
    this = (void *)0x0;
    ppbVar4 = (byte **)((int)param_1 + 1);
    do {
      param_3 = ppbVar4;
      pvVar7 = this;
      this = (void *)((int)pvVar7 + 1);
      ppbVar4 = (byte **)((int)param_3 + 1);
    } while (*(byte *)param_3 == bVar1);
    if ((char)bVar1 < 'e') {
      if (bVar1 == 100) {
        if (pvVar7 == (void *)0x0) {
          DAT_01415c6c = 1;
        }
        else if (pvVar7 != (void *)0x1) {
          if (pvVar7 == (void *)0x2) {
            param_4._0_1_ = 'a';
          }
          else {
            if (pvVar7 != (void *)0x3) goto LAB_0140dc7e;
            param_4._0_1_ = 'A';
          }
          goto LAB_0140deb4;
        }
        param_4._0_1_ = 'd';
        goto LAB_0140deb4;
      }
      if (bVar1 != 0x27) {
        if (bVar1 != 0x41) {
          if (bVar1 == 0x48) {
            if (pvVar7 == (void *)0x0) {
              DAT_01415c6c = 1;
            }
            else if (this != (void *)0x2) goto LAB_0140dc7e;
            param_4._0_1_ = 'H';
            goto LAB_0140deb4;
          }
          if (bVar1 == 0x4d) {
            if (pvVar7 == (void *)0x0) {
              DAT_01415c6c = 1;
            }
            else if (pvVar7 != (void *)0x1) {
              if (pvVar7 == (void *)0x2) {
                param_4._0_1_ = 'b';
              }
              else {
                if (pvVar7 != (void *)0x3) goto LAB_0140dc7e;
                param_4._0_1_ = 'B';
              }
              goto LAB_0140deb4;
            }
            param_4._0_1_ = 'm';
            goto LAB_0140deb4;
          }
          if (bVar1 != 0x61) goto LAB_0140dc7e;
        }
        this_00 = "am/pm";
        uVar5 = FUN_0140a6c0(this,param_1,(byte *)"am/pm");
        if (uVar5 == 0) {
          param_3 = (byte **)((int)param_1 + 5);
        }
        else {
          uVar5 = FUN_0140a6c0(this_00,param_1,&DAT_0140ff18);
          if (uVar5 == 0) {
            param_3 = (byte **)((int)param_1 + 3);
          }
        }
        param_4._0_1_ = 'p';
        goto LAB_0140deb4;
      }
      if (((uint)this & 1) == 0) {
        param_3 = (byte **)((int)param_1 + (int)this);
      }
      else {
        param_3 = (byte **)((int)param_1 + (int)this);
        while( true ) {
          bVar1 = *(byte *)param_3;
          if ((bVar1 == 0) || (*puVar3 == 0)) goto LAB_0140dca4;
          if (bVar1 == 0x27) break;
          if (((PTR_DAT_014137b8[(uint)bVar1 * 2 + 1] & 0x80) != 0) && (1 < *puVar3)) {
            **ppbVar2 = bVar1;
            *ppbVar2 = *ppbVar2 + 1;
            param_3 = (byte **)((int)param_3 + 1);
            *puVar3 = *puVar3 - 1;
          }
          **ppbVar2 = *(byte *)param_3;
          *ppbVar2 = *ppbVar2 + 1;
          param_3 = (byte **)((int)param_3 + 1);
          *puVar3 = *puVar3 - 1;
        }
        param_3 = (byte **)((int)param_3 + 1);
      }
    }
    else {
      if (bVar1 == 0x68) {
        if (pvVar7 == (void *)0x0) {
          DAT_01415c6c = 1;
        }
        else if (this != (void *)0x2) goto LAB_0140dc7e;
        param_4._0_1_ = 'I';
      }
      else if (bVar1 == 0x6d) {
        if (pvVar7 == (void *)0x0) {
          DAT_01415c6c = 1;
        }
        else if (this != (void *)0x2) goto LAB_0140dc7e;
        param_4._0_1_ = 'M';
      }
      else if (bVar1 == 0x73) {
        if (pvVar7 == (void *)0x0) {
          DAT_01415c6c = 1;
        }
        else if (this != (void *)0x2) goto LAB_0140dc7e;
        param_4._0_1_ = 'S';
      }
      else {
        if (bVar1 == 0x74) {
          if (*(int *)(param_2 + 8) < 0xc) {
            pbVar6 = *(byte **)(param_5 + 0x98);
          }
          else {
            pbVar6 = *(byte **)(param_5 + 0x9c);
          }
          while ((0 < (int)this && (*puVar3 != 0))) {
            if (((PTR_DAT_014137b8[(uint)*pbVar6 * 2 + 1] & 0x80) != 0) && (1 < *puVar3)) {
              **ppbVar2 = *pbVar6;
              *ppbVar2 = *ppbVar2 + 1;
              pbVar6 = pbVar6 + 1;
              *puVar3 = *puVar3 - 1;
            }
            **ppbVar2 = *pbVar6;
            *ppbVar2 = *ppbVar2 + 1;
            pbVar6 = pbVar6 + 1;
            *puVar3 = *puVar3 - 1;
            this = (void *)((int)this + -1);
          }
          goto LAB_0140dca4;
        }
        if (bVar1 != 0x79) {
LAB_0140dc7e:
          if ((PTR_DAT_014137b8[(uint)bVar1 * 2 + 1] & 0x80) != 0) {
            **ppbVar2 = bVar1;
            *ppbVar2 = *ppbVar2 + 1;
            *puVar3 = *puVar3 - 1;
            param_1 = (byte *)(byte **)((int)param_1 + 1);
          }
          **ppbVar2 = *param_1;
          *ppbVar2 = *ppbVar2 + 1;
          param_3 = (byte **)((int)param_1 + 1);
          *puVar3 = *puVar3 - 1;
          goto LAB_0140dca4;
        }
        if (pvVar7 == (void *)0x1) {
          param_4._0_1_ = 'y';
        }
        else {
          if (pvVar7 != (void *)0x3) goto LAB_0140dc7e;
          param_4._0_1_ = 'Y';
        }
      }
LAB_0140deb4:
      FUN_0140d72c((char)param_4,(int *)param_2,ppbVar2,puVar3,param_5);
    }
LAB_0140dca4:
    bVar1 = *(byte *)param_3;
    param_1 = (byte *)param_3;
  } while( true );
}



undefined4 __cdecl FUN_0140dec9(int param_1,LCID param_2,LCTYPE param_3,char **param_4)

{
  byte bVar1;
  bool bVar2;
  size_t sVar3;
  DWORD DVar4;
  CHAR *_Source;
  char *_Dest;
  int iVar5;
  uint uVar6;
  void *extraout_ECX;
  undefined *puVar7;
  void *this;
  byte *pbVar8;
  CHAR local_84 [128];
  
  if (param_1 != 1) {
    if (param_1 != 0) {
      return 0xffffffff;
    }
    pbVar8 = &DAT_01415c4c;
    iVar5 = FUN_0140e95f(param_2,param_3,(LPWSTR)&DAT_01415c4c,4,0);
    if (iVar5 != 0) {
      *(undefined *)param_4 = 0;
      this = extraout_ECX;
      while( true ) {
        bVar1 = *pbVar8;
        if (DAT_014139c4 < 2) {
          uVar6 = (byte)PTR_DAT_014137b8[(uint)bVar1 * 2] & 4;
          puVar7 = PTR_DAT_014137b8;
        }
        else {
          puVar7 = (undefined *)0x0;
          uVar6 = FUN_01405ac0(this,(uint)bVar1,4);
        }
        if (uVar6 == 0) break;
        this = (void *)CONCAT31((int3)((uint)puVar7 >> 8),10);
        pbVar8 = pbVar8 + 2;
        *(byte *)param_4 = *(char *)param_4 * '\n' + bVar1 + -0x30;
        if (0x1415c53 < (int)pbVar8) {
          return 0;
        }
      }
      return 0;
    }
    return 0xffffffff;
  }
  _Source = local_84;
  bVar2 = false;
  sVar3 = FUN_0140ea72(param_2,param_3,local_84,0x80,0);
  if (sVar3 == 0) {
    DVar4 = GetLastError();
    if (DVar4 != 0x7a) {
      return 0xffffffff;
    }
    sVar3 = FUN_0140ea72(param_2,param_3,(LPSTR)0x0,0,0);
    if (sVar3 == 0) {
      return 0xffffffff;
    }
    _Source = (CHAR *)_malloc(sVar3);
    if (_Source == (LPSTR)0x0) {
      return 0xffffffff;
    }
    bVar2 = true;
    sVar3 = FUN_0140ea72(param_2,param_3,_Source,sVar3,0);
    if (sVar3 == 0) goto LAB_0140df67;
  }
  _Dest = (char *)_malloc(sVar3);
  *param_4 = _Dest;
  if (_Dest != (char *)0x0) {
    _strncpy(_Dest,_Source,sVar3);
    if (bVar2) {
      FUN_01404c4e(_Source);
    }
    return 0;
  }
  if (!bVar2) {
    return 0xffffffff;
  }
LAB_0140df67:
  FUN_01404c4e(_Source);
  return 0xffffffff;
}



BOOL __cdecl
FUN_0140e007(DWORD param_1,LPCWSTR param_2,int param_3,undefined4 *param_4,UINT param_5,LCID param_6
            )

{
  undefined *puVar1;
  BOOL BVar2;
  int iVar3;
  CHAR unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  LPCSTR local_30;
  size_t local_2c;
  WORD local_20 [2];
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140ff28;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffc4;
  iVar3 = DAT_01415c58;
  puVar1 = &stack0xffffffc4;
  if (DAT_01415c58 == 0) {
    BVar2 = GetStringTypeW(1,L"",1,local_20);
    iVar3 = 1;
    puVar1 = local_1c;
    if (BVar2 != 0) goto LAB_0140e076;
    BVar2 = GetStringTypeA(0,1,"",1,local_20);
    if (BVar2 != 0) {
      iVar3 = 2;
      puVar1 = local_1c;
      goto LAB_0140e076;
    }
  }
  else {
LAB_0140e076:
    local_1c = puVar1;
    DAT_01415c58 = iVar3;
    if (DAT_01415c58 == 1) {
      BVar2 = GetStringTypeW(param_1,param_2,param_3,(LPWORD)param_4);
      goto LAB_0140e1ba;
    }
    if (DAT_01415c58 == 2) {
      if (param_5 == 0) {
        param_5 = DAT_01415bd0;
      }
      local_30 = &stack0xffffffc4;
      local_2c = WideCharToMultiByte(param_5,0x220,param_2,param_3,(LPSTR)0x0,0,(LPCSTR)0x0,
                                     (LPBOOL)0x0);
      if (local_2c != 0) {
        local_8 = 0;
        FUN_014028c0(unaff_DI);
        local_1c = &stack0xffffffc4;
        Initialize_Memory(&stack0xffffffc4,0,local_2c);
        local_8 = 0xffffffff;
        if (&stack0x00000000 != (undefined *)0x3c) {
          iVar3 = WideCharToMultiByte(param_5,0x220,param_2,param_3,&stack0xffffffc4,local_2c,
                                      (LPCSTR)0x0,(LPBOOL)0x0);
          if (iVar3 != 0) {
            local_8 = 1;
            FUN_014028c0(unaff_DI);
            local_8 = 0xffffffff;
            if (&stack0x00000000 != (undefined *)0x3c) {
              if (param_6 == 0) {
                param_6 = DAT_01415bc0;
              }
              local_1c = &stack0xffffffc4;
              *(short *)(&stack0xffffffc4 + param_3 * 2) = -1;
              local_20[param_3 + -0xf] = 0xffff;
              BVar2 = GetStringTypeA(param_6,param_1,local_30,local_2c,(LPWORD)&stack0xffffffc4);
              if ((local_20[param_3 + -0xf] != 0xffff) &&
                 (*(short *)(&stack0xffffffc4 + param_3 * 2) == -1)) {
                FUN_01406fc0(param_4,(undefined4 *)&stack0xffffffc4,param_3 * 2);
                goto LAB_0140e1ba;
              }
            }
          }
        }
      }
    }
  }
  BVar2 = 0;
LAB_0140e1ba:
  *unaff_FS_OFFSET = local_14;
  return BVar2;
}



char * __cdecl FUN_0140e1cc(uint param_1,char *param_2,uint param_3)

{
  int iVar1;
  
  if ((param_3 == 10) && ((int)param_1 < 0)) {
    iVar1 = 1;
    param_3 = 10;
  }
  else {
    iVar1 = 0;
  }
  FUN_0140e1f9(param_1,param_2,param_3,iVar1);
  return param_2;
}



void __cdecl FUN_0140e1f9(uint param_1,char *param_2,uint param_3,int param_4)

{
  ulonglong uVar1;
  char *pcVar2;
  char *pcVar3;
  char cVar4;
  
  pcVar2 = param_2;
  if (param_4 != 0) {
    *param_2 = '-';
    param_2 = param_2 + 1;
    param_1 = -param_1;
    pcVar2 = param_2;
  }
  do {
    pcVar3 = pcVar2;
    uVar1 = (ulonglong)param_1;
    param_1 = param_1 / param_3;
    cVar4 = (char)(uVar1 % (ulonglong)param_3);
    if ((uint)(uVar1 % (ulonglong)param_3) < 10) {
      cVar4 = cVar4 + '0';
    }
    else {
      cVar4 = cVar4 + 'W';
    }
    *pcVar3 = cVar4;
    pcVar2 = pcVar3 + 1;
  } while (param_1 != 0);
  pcVar3[1] = '\0';
  do {
    cVar4 = *pcVar3;
    *pcVar3 = *param_2;
    *param_2 = cVar4;
    pcVar3 = pcVar3 + -1;
    param_2 = param_2 + 1;
  } while (param_2 < pcVar3);
  return;
}



char * __cdecl FUN_0140e255(uint param_1,char *param_2,uint param_3)

{
  int iVar1;
  
  iVar1 = 0;
  if ((param_3 == 10) && ((int)param_1 < 0)) {
    iVar1 = 1;
  }
  FUN_0140e1f9(param_1,param_2,param_3,iVar1);
  return param_2;
}



char * __cdecl FUN_0140e29a(int param_1,int param_2,char *param_3,uint param_4)

{
  int iVar1;
  
  iVar1 = 0;
  if (((param_4 == 10) && (param_2 < 1)) && (param_2 < 0)) {
    iVar1 = 1;
  }
  FUN_0140e2cb(param_1,param_2,param_3,param_4,iVar1);
  return param_3;
}



void FUN_0140e2cb(int param_1,int param_2,char *param_3,uint param_4,int param_5)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  bool bVar4;
  undefined8 uVar5;
  longlong lVar6;
  uint uVar7;
  
  if (param_5 != 0) {
    *param_3 = '-';
    param_3 = param_3 + 1;
    bVar4 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(param_2 + (uint)bVar4);
  }
  lVar6 = CONCAT44(param_2,param_1);
  pcVar1 = param_3;
  do {
    pcVar3 = pcVar1;
    uVar7 = (uint)((ulonglong)lVar6 >> 0x20);
    uVar5 = __aullrem((uint)lVar6,uVar7,param_4,0);
    lVar6 = __aulldiv((uint)lVar6,uVar7,param_4,0);
    if ((uint)uVar5 < 10) {
      cVar2 = (char)uVar5 + '0';
    }
    else {
      cVar2 = (char)uVar5 + 'W';
    }
    *pcVar3 = cVar2;
    pcVar1 = pcVar3 + 1;
  } while (lVar6 != 0);
  pcVar3[1] = '\0';
  do {
    cVar2 = *pcVar3;
    *pcVar3 = *param_3;
    *param_3 = cVar2;
    pcVar3 = pcVar3 + -1;
    param_3 = param_3 + 1;
  } while (param_3 < pcVar3);
  return;
}



char * __cdecl FUN_0140e351(int param_1,int param_2,char *param_3,uint param_4)

{
  FUN_0140e2cb(param_1,param_2,param_3,param_4,0);
  return param_3;
}



void * __cdecl FUN_0140e370(byte *param_1,char *param_2,void *param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  void *this;
  uint uVar6;
  bool bVar7;
  uint uVar8;
  
  iVar2 = DAT_01415c74;
  if (param_3 != (void *)0x0) {
    if (DAT_01415bc0 == 0) {
      do {
        bVar3 = *param_1;
        cVar1 = *param_2;
        uVar4 = CONCAT11(bVar3,cVar1);
        if (bVar3 == 0) break;
        uVar4 = CONCAT11(bVar3,cVar1);
        uVar6 = (uint)uVar4;
        if (cVar1 == '\0') break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar6 = (uint)CONCAT11(bVar3 + 0x20,cVar1);
        }
        uVar4 = (ushort)uVar6;
        bVar3 = (byte)uVar6;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar4 = (ushort)CONCAT31((int3)(uVar6 >> 8),bVar3 + 0x20);
        }
        bVar3 = (byte)(uVar4 >> 8);
        bVar7 = bVar3 < (byte)uVar4;
        if (bVar3 != (byte)uVar4) goto LAB_0140e3cf;
        param_3 = (void *)((int)param_3 + -1);
      } while (param_3 != (void *)0x0);
      param_3 = (void *)0x0;
      bVar3 = (byte)(uVar4 >> 8);
      bVar7 = bVar3 < (byte)uVar4;
      if (bVar3 != (byte)uVar4) {
LAB_0140e3cf:
        param_3 = (void *)0xffffffff;
        if (!bVar7) {
          param_3 = (void *)0x1;
        }
      }
    }
    else {
      LOCK();
      DAT_01415c74 = DAT_01415c74 + 1;
      UNLOCK();
      bVar7 = 0 < DAT_01415c70;
      if (bVar7) {
        LOCK();
        UNLOCK();
        DAT_01415c74 = iVar2;
        critical_code_area_executor(0x13);
      }
      uVar8 = (uint)bVar7;
      uVar5 = 0;
      uVar6 = 0;
      do {
        uVar5 = CONCAT31((int3)(uVar5 >> 8),*param_1);
        uVar6 = CONCAT31((int3)(uVar6 >> 8),*param_2);
        if ((uVar5 == 0) || (uVar6 == 0)) break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        uVar6 = FUN_0140bb32(param_3,uVar6);
        uVar5 = FUN_0140bb32(this,uVar5);
        bVar7 = uVar5 < uVar6;
        if (uVar5 != uVar6) goto LAB_0140e445;
        param_3 = (void *)((int)param_3 + -1);
      } while (param_3 != (void *)0x0);
      param_3 = (void *)0x0;
      bVar7 = uVar5 < uVar6;
      if (uVar5 != uVar6) {
LAB_0140e445:
        param_3 = (void *)0xffffffff;
        if (!bVar7) {
          param_3 = (void *)0x1;
        }
      }
      if (uVar8 == 0) {
        LOCK();
        DAT_01415c74 = DAT_01415c74 + -1;
        UNLOCK();
      }
      else {
        endCriticalFromID(0x13);
      }
    }
  }
  return param_3;
}



int __cdecl
FUN_0140e471(LCID param_1,DWORD param_2,byte *param_3,int param_4,byte *param_5,int param_6,
            UINT param_7)

{
  undefined *puVar1;
  int iVar2;
  BOOL BVar3;
  BYTE *pBVar4;
  undefined unaff_DI;
  int iVar5;
  undefined4 *unaff_FS_OFFSET;
  _cpinfo local_40;
  undefined *local_2c;
  PCNZWCH local_28;
  int local_24;
  int local_20;
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140ff40;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffb0;
  iVar5 = 1;
  puVar1 = &stack0xffffffb0;
  if (DAT_01415c5c == 0) {
    iVar2 = CompareStringW(0,0,L"",1,L"",1);
    if (iVar2 != 0) {
      DAT_01415c5c = 1;
      puVar1 = local_1c;
      goto LAB_0140e4e4;
    }
    iVar2 = CompareStringA(0,0,"",1,"",1);
    if (iVar2 != 0) {
      DAT_01415c5c = 2;
      puVar1 = local_1c;
      goto LAB_0140e4e4;
    }
  }
  else {
LAB_0140e4e4:
    local_1c = puVar1;
    if (0 < param_4) {
      param_4 = FUN_0140e6ee((char *)param_3,param_4);
    }
    if (0 < param_6) {
      param_6 = FUN_0140e6ee((char *)param_5,param_6);
    }
    if (DAT_01415c5c == 2) {
      iVar5 = CompareStringA(param_1,param_2,(PCNZCH)param_3,param_4,(PCNZCH)param_5,param_6);
      goto LAB_0140e6dc;
    }
    if (DAT_01415c5c == 1) {
      if (param_7 == 0) {
        param_7 = DAT_01415bd0;
      }
      if ((param_4 == 0) || (param_6 == 0)) {
        if (param_4 == param_6) {
LAB_0140e55c:
          iVar5 = 2;
          goto LAB_0140e6dc;
        }
        if (1 < param_6) goto LAB_0140e6dc;
        if (param_4 < 2) {
          BVar3 = GetCPInfo(param_7,&local_40);
          if (BVar3 == 0) goto LAB_0140e6da;
          if (param_4 < 1) {
            if (0 < param_6) {
              if (1 < local_40.MaxCharSize) {
                pBVar4 = local_40.LeadByte;
                while ((local_40.LeadByte[0] != 0 && (pBVar4[1] != 0))) {
                  if ((*pBVar4 <= *param_5) && (*param_5 <= pBVar4[1])) goto LAB_0140e55c;
                  pBVar4 = pBVar4 + 2;
                  local_40.LeadByte[0] = *pBVar4;
                }
              }
              goto LAB_0140e6dc;
            }
            goto LAB_0140e5ef;
          }
          if (1 < local_40.MaxCharSize) {
            pBVar4 = local_40.LeadByte;
            while ((local_40.LeadByte[0] != 0 && (pBVar4[1] != 0))) {
              if ((*pBVar4 <= *param_3) && (*param_3 <= pBVar4[1])) goto LAB_0140e55c;
              pBVar4 = pBVar4 + 2;
              local_40.LeadByte[0] = *pBVar4;
            }
          }
        }
        iVar5 = 3;
        goto LAB_0140e6dc;
      }
LAB_0140e5ef:
      local_20 = MultiByteToWideChar(param_7,9,(LPCSTR)param_3,param_4,(LPWSTR)0x0,0);
      if (local_20 != 0) {
        local_8 = 0;
        FUN_014028c0(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x50) &&
           (local_28 = (PCNZWCH)&stack0xffffffb0, local_1c = &stack0xffffffb0,
           iVar5 = MultiByteToWideChar(param_7,1,(LPCSTR)param_3,param_4,(LPWSTR)&stack0xffffffb0,
                                       local_20), iVar5 != 0)) {
          iVar5 = MultiByteToWideChar(param_7,9,(LPCSTR)param_5,param_6,(LPWSTR)0x0,0);
          if (iVar5 != 0) {
            local_8 = 1;
            local_24 = iVar5;
            FUN_014028c0(unaff_DI);
            local_8 = 0xffffffff;
            if ((&stack0x00000000 != (undefined *)0x50) &&
               (local_2c = &stack0xffffffb0, local_1c = &stack0xffffffb0,
               iVar2 = MultiByteToWideChar(param_7,1,(LPCSTR)param_5,param_6,
                                           (LPWSTR)&stack0xffffffb0,iVar5), iVar2 != 0)) {
              iVar5 = CompareStringW(param_1,param_2,local_28,local_20,(PCNZWCH)&stack0xffffffb0,
                                     iVar5);
              goto LAB_0140e6dc;
            }
          }
        }
      }
    }
  }
LAB_0140e6da:
  iVar5 = 0;
LAB_0140e6dc:
  *unaff_FS_OFFSET = local_14;
  return iVar5;
}



int __cdecl FUN_0140e6ee(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = param_1;
  iVar2 = param_2;
  if (param_2 != 0) {
    do {
      iVar2 = iVar2 + -1;
      if (*pcVar1 == '\0') break;
      pcVar1 = pcVar1 + 1;
    } while (iVar2 != 0);
  }
  if (*pcVar1 == '\0') {
    return (int)pcVar1 - (int)param_1;
  }
  return param_2;
}



undefined4 __cdecl FUN_0140e719(uint *param_1,int param_2)

{
  uint *puVar1;
  int iVar2;
  uint **ppuVar3;
  size_t sVar4;
  uint *lpName;
  undefined *puVar5;
  uint **ppuVar6;
  bool bVar7;
  
  if (param_1 == (uint *)0x0) {
    return 0xffffffff;
  }
  puVar1 = FUN_0140aab0(param_1,0x3d);
  if (puVar1 == (uint *)0x0) {
    return 0xffffffff;
  }
  if (param_1 == puVar1) {
    return 0xffffffff;
  }
  bVar7 = *(char *)((int)puVar1 + 1) == '\0';
  if (DAT_0141593c == DAT_01415940) {
    DAT_0141593c = FUN_0140e8f8(DAT_0141593c);
  }
  if (DAT_0141593c == (uint **)0x0) {
    if ((param_2 == 0) || (DAT_01415944 == (undefined4 *)0x0)) {
      if (bVar7) {
        return 0;
      }
      DAT_0141593c = (uint **)_malloc(4);
      if (DAT_0141593c == (uint **)0x0) {
        return 0xffffffff;
      }
      *DAT_0141593c = (uint *)0x0;
      if (DAT_01415944 == (undefined4 *)0x0) {
        DAT_01415944 = (undefined4 *)_malloc(4);
        if (DAT_01415944 == (undefined4 *)0x0) {
          return 0xffffffff;
        }
        *DAT_01415944 = 0;
      }
    }
    else {
      iVar2 = FUN_0140d253();
      if (iVar2 != 0) {
        return 0xffffffff;
      }
    }
  }
  ppuVar3 = DAT_0141593c;
  iVar2 = FUN_0140e8a0((uchar *)param_1,(int)puVar1 - (int)param_1);
  if ((iVar2 < 0) || (*ppuVar3 == (uint *)0x0)) {
    if (bVar7) {
      return 0;
    }
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    ppuVar3 = (uint **)FUN_01405580((int **)ppuVar3,(uint *)(iVar2 * 4 + 8));
    if (ppuVar3 == (uint **)0x0) {
      return 0xffffffff;
    }
    ppuVar3[iVar2] = param_1;
    ppuVar3[iVar2 + 1] = (uint *)0x0;
  }
  else {
    if (!bVar7) {
      ppuVar3[iVar2] = param_1;
      goto LAB_0140e84d;
    }
    ppuVar6 = ppuVar3 + iVar2;
    FUN_01404c4e((undefined *)ppuVar3[iVar2]);
    for (; *ppuVar6 != (uint *)0x0; ppuVar6 = ppuVar6 + 1) {
      iVar2 = iVar2 + 1;
      *ppuVar6 = ppuVar6[1];
    }
    ppuVar3 = (uint **)FUN_01405580((int **)ppuVar3,(uint *)(iVar2 << 2));
    if (ppuVar3 == (uint **)0x0) goto LAB_0140e84d;
  }
  DAT_0141593c = ppuVar3;
LAB_0140e84d:
  if (param_2 != 0) {
    sVar4 = _strlen((char *)param_1);
    lpName = (uint *)_malloc(sVar4 + 2);
    if (lpName != (uint *)0x0) {
      FUN_014028f0(lpName,param_1);
      puVar5 = (undefined *)(((int)lpName - (int)param_1) + (int)puVar1);
      *puVar5 = 0;
      SetEnvironmentVariableA((LPCSTR)lpName,(LPCSTR)(~-(uint)bVar7 & (uint)(puVar5 + 1)));
      FUN_01404c4e((undefined *)lpName);
    }
  }
  return 0;
}



int __cdecl FUN_0140e8a0(uchar *param_1,size_t param_2)

{
  uchar *_Str2;
  int iVar1;
  uchar **ppuVar2;
  
  _Str2 = *DAT_0141593c;
  ppuVar2 = DAT_0141593c;
  while( true ) {
    if (_Str2 == (uchar *)0x0) {
      return -((int)ppuVar2 - (int)DAT_0141593c >> 2);
    }
    iVar1 = __mbsnbicoll(param_1,_Str2,param_2);
    if ((iVar1 == 0) && (((*ppuVar2)[param_2] == '=' || ((*ppuVar2)[param_2] == '\0')))) break;
    _Str2 = ppuVar2[1];
    ppuVar2 = ppuVar2 + 1;
  }
  return (int)ppuVar2 - (int)DAT_0141593c >> 2;
}



uint ** __cdecl FUN_0140e8f8(uint **param_1)

{
  uint **ppuVar1;
  uint *puVar2;
  int iVar3;
  uint **ppuVar4;
  
  iVar3 = 0;
  if (param_1 != (uint **)0x0) {
    puVar2 = *param_1;
    ppuVar1 = param_1;
    while (puVar2 != (uint *)0x0) {
      ppuVar1 = ppuVar1 + 1;
      iVar3 = iVar3 + 1;
      puVar2 = *ppuVar1;
    }
    ppuVar1 = (uint **)_malloc(iVar3 * 4 + 4);
    if (ppuVar1 == (uint **)0x0) {
      __amsg_exit(9);
    }
    puVar2 = *param_1;
    ppuVar4 = ppuVar1;
    while (puVar2 != (uint *)0x0) {
      param_1 = param_1 + 1;
      puVar2 = FUN_0140eb90(puVar2);
      *ppuVar4 = puVar2;
      ppuVar4 = ppuVar4 + 1;
      puVar2 = *param_1;
    }
    *ppuVar4 = (uint *)0x0;
    return ppuVar1;
  }
  return (uint **)0x0;
}



int __cdecl FUN_0140e95f(LCID param_1,LCTYPE param_2,LPWSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  CHAR unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140ff58;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_01415c60 == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_01415c60 = 1;
      goto LAB_0140e9be;
    }
    iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_01415c60 = 2;
      goto LAB_0140e9be;
    }
  }
  else {
LAB_0140e9be:
    if (DAT_01415c60 == 1) {
      iVar1 = GetLocaleInfoW(param_1,param_2,param_3,param_4);
      goto LAB_0140ea60;
    }
    if (DAT_01415c60 == 2) {
      if (param_5 == 0) {
        param_5 = DAT_01415bd0;
      }
      iVar1 = GetLocaleInfoA(param_1,param_2,(LPSTR)0x0,0);
      if (iVar1 != 0) {
        local_8 = 0;
        FUN_014028c0(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x34) &&
           (iVar1 = GetLocaleInfoA(param_1,param_2,&stack0xffffffcc,iVar1), iVar1 != 0)) {
          if (param_4 == 0) {
            param_4 = 0;
            param_3 = (LPWSTR)0x0;
          }
          iVar1 = MultiByteToWideChar(param_5,1,&stack0xffffffcc,-1,param_3,param_4);
          goto LAB_0140ea60;
        }
      }
    }
  }
  iVar1 = 0;
LAB_0140ea60:
  *unaff_FS_OFFSET = local_14;
  return iVar1;
}



int __cdecl FUN_0140ea72(LCID param_1,LCTYPE param_2,LPSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0140ff68;
  puStack_10 = &LAB_014073f0;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_01415c64 == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_01415c64 = 1;
      goto LAB_0140ead1;
    }
    iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_01415c64 = 2;
      goto LAB_0140ead1;
    }
  }
  else {
LAB_0140ead1:
    if (DAT_01415c64 == 2) {
      iVar1 = GetLocaleInfoA(param_1,param_2,param_3,param_4);
      goto LAB_0140eb7e;
    }
    if (DAT_01415c64 == 1) {
      if (param_5 == 0) {
        param_5 = DAT_01415bd0;
      }
      iVar1 = GetLocaleInfoW(param_1,param_2,(LPWSTR)0x0,0);
      if (iVar1 != 0) {
        local_8 = 0;
        FUN_014028c0(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x34) &&
           (iVar1 = GetLocaleInfoW(param_1,param_2,(LPWSTR)&stack0xffffffcc,iVar1), iVar1 != 0)) {
          if (param_4 == 0) {
            param_4 = 0;
            param_3 = (LPSTR)0x0;
          }
          iVar1 = WideCharToMultiByte(param_5,0x220,(LPCWSTR)&stack0xffffffcc,-1,param_3,param_4,
                                      (LPCSTR)0x0,(LPBOOL)0x0);
          goto LAB_0140eb7e;
        }
      }
    }
  }
  iVar1 = 0;
LAB_0140eb7e:
  *unaff_FS_OFFSET = local_14;
  return iVar1;
}



uint * __cdecl FUN_0140eb90(uint *param_1)

{
  size_t sVar1;
  uint *puVar2;
  
  if (param_1 != (uint *)0x0) {
    sVar1 = _strlen((char *)param_1);
    puVar2 = (uint *)_malloc(sVar1 + 1);
    if (puVar2 != (uint *)0x0) {
      puVar2 = FUN_014028f0(puVar2,param_1);
      return puVar2;
    }
  }
  return (uint *)0x0;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0140ec6e. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



undefined4 __cdecl FUN_0140ed8e(LPCSTR param_1)

{
  BOOL BVar1;
  uint uVar2;
  
  BVar1 = DeleteFileA(param_1);
  if (BVar1 == 0) {
    uVar2 = GetLastError();
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 != 0) {
    FUN_01406bf3(uVar2);
    return 0xffffffff;
  }
  return 0;
}



void __cdecl FUN_0140edb8(LPCSTR param_1)

{
  FUN_0140ed8e(param_1);
  return;
}


