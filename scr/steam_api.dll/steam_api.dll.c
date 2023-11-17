#include "steam_api.dll.h"



undefined4 FUN_3b401000(undefined4 param_1)

{
  return param_1;
}



undefined4 * __thiscall FUN_3b401020(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_3b4111a0;
  FUN_3b404995((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_3b404a3d(this);
  }
  return (undefined4 *)this;
}



void __cdecl SteamAPI_SetTryCatchCallbacks(undefined param_1)

{
                    // 0x1050  15  SteamAPI_SetTryCatchCallbacks
  DAT_3b416008 = param_1;
  return;
}



void __cdecl FUN_3b401060(int param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 8);
  cVar1 = *(char *)(iVar2 + 0x15);
  while (cVar1 == '\0') {
    iVar2 = *(int *)(iVar2 + 8);
    cVar1 = *(char *)(iVar2 + 0x15);
  }
  return;
}



void __cdecl FUN_3b401080(int **param_1)

{
  char cVar1;
  int *piVar2;
  
  piVar2 = *param_1;
  cVar1 = *(char *)((int)piVar2 + 0x15);
  while (cVar1 == '\0') {
    piVar2 = (int *)*piVar2;
    cVar1 = *(char *)((int)piVar2 + 0x15);
  }
  return;
}



void __cdecl FUN_3b4010a0(int param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 8);
  cVar1 = *(char *)(iVar2 + 0x21);
  while (cVar1 == '\0') {
    iVar2 = *(int *)(iVar2 + 8);
    cVar1 = *(char *)(iVar2 + 0x21);
  }
  return;
}



void __cdecl FUN_3b4010c0(int **param_1)

{
  char cVar1;
  int *piVar2;
  
  piVar2 = *param_1;
  cVar1 = *(char *)((int)piVar2 + 0x21);
  while (cVar1 == '\0') {
    piVar2 = (int *)*piVar2;
    cVar1 = *(char *)((int)piVar2 + 0x21);
  }
  return;
}



void __fastcall FUN_3b4010e0(int **param_1)

{
  char cVar1;
  int *piVar2;
  int **ppiVar3;
  int **ppiVar4;
  
  piVar2 = *param_1;
  if (*(char *)((int)piVar2 + 0x15) == '\0') {
    ppiVar3 = (int **)piVar2[2];
    if (*(char *)((int)ppiVar3 + 0x15) == '\0') {
      cVar1 = *(char *)((int)*ppiVar3 + 0x15);
      ppiVar4 = (int **)*ppiVar3;
      while (cVar1 == '\0') {
        cVar1 = *(char *)((int)*ppiVar4 + 0x15);
        ppiVar3 = ppiVar4;
        ppiVar4 = (int **)*ppiVar4;
      }
      *param_1 = (int *)ppiVar3;
      return;
    }
    piVar2 = (int *)piVar2[1];
    cVar1 = *(char *)((int)piVar2 + 0x15);
    while ((cVar1 == '\0' && (*param_1 == (int *)piVar2[2]))) {
      *param_1 = piVar2;
      piVar2 = (int *)piVar2[1];
      cVar1 = *(char *)((int)piVar2 + 0x15);
    }
    *param_1 = piVar2;
  }
  return;
}



void __fastcall FUN_3b401130(int **param_1)

{
  char cVar1;
  int *piVar2;
  int **ppiVar3;
  int **ppiVar4;
  
  piVar2 = *param_1;
  if (*(char *)((int)piVar2 + 0x21) == '\0') {
    ppiVar3 = (int **)piVar2[2];
    if (*(char *)((int)ppiVar3 + 0x21) == '\0') {
      cVar1 = *(char *)((int)*ppiVar3 + 0x21);
      ppiVar4 = (int **)*ppiVar3;
      while (cVar1 == '\0') {
        cVar1 = *(char *)((int)*ppiVar4 + 0x21);
        ppiVar3 = ppiVar4;
        ppiVar4 = (int **)*ppiVar4;
      }
      *param_1 = (int *)ppiVar3;
      return;
    }
    piVar2 = (int *)piVar2[1];
    cVar1 = *(char *)((int)piVar2 + 0x21);
    while ((cVar1 == '\0' && (*param_1 == (int *)piVar2[2]))) {
      *param_1 = piVar2;
      piVar2 = (int *)piVar2[1];
      cVar1 = *(char *)((int)piVar2 + 0x21);
    }
    *param_1 = piVar2;
  }
  return;
}



undefined4 * __thiscall FUN_3b401180(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_3b4111a0;
  return (undefined4 *)this;
}



void __fastcall FUN_3b4011a0(int **param_1)

{
  char cVar1;
  int **ppiVar2;
  int *piVar3;
  int *piVar4;
  int **ppiVar5;
  
  ppiVar2 = (int **)*param_1;
  if (*(char *)((int)ppiVar2 + 0x21) != '\0') {
    *param_1 = ppiVar2[2];
    return;
  }
  ppiVar5 = (int **)*ppiVar2;
  if (*(char *)((int)ppiVar5 + 0x21) == '\0') {
    piVar3 = ppiVar5[2];
    if (*(char *)((int)ppiVar5[2] + 0x21) == '\0') {
      do {
        piVar4 = piVar3;
        piVar3 = (int *)piVar4[2];
      } while (*(char *)((int)piVar3 + 0x21) == '\0');
      *param_1 = piVar4;
      return;
    }
  }
  else {
    ppiVar5 = (int **)ppiVar2[1];
    cVar1 = *(char *)((int)ppiVar5 + 0x21);
    while ((cVar1 == '\0' && (*param_1 == *ppiVar5))) {
      *param_1 = (int *)ppiVar5;
      ppiVar5 = (int **)ppiVar5[1];
      cVar1 = *(char *)((int)ppiVar5 + 0x21);
    }
    if (*(char *)((int)*param_1 + 0x21) != '\0') {
      return;
    }
  }
  *param_1 = (int *)ppiVar5;
  return;
}



void __fastcall FUN_3b401220(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x3b40122c. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(param_1 + 0x10))();
  return;
}



void __thiscall FUN_3b401260(void *this,undefined4 param_1)

{
  (**(code **)((int)this + 0x10))(param_1);
  return;
}



void __thiscall FUN_3b401280(void *this,int *param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = *param_1;
  *param_1 = *(int *)(iVar1 + 8);
  if (*(char *)(*(int *)(iVar1 + 8) + 0x15) == '\0') {
    *(int **)(*(int *)(iVar1 + 8) + 4) = param_1;
  }
  *(int *)(iVar1 + 4) = param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int *)(*(int *)((int)this + 4) + 4) = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  piVar2 = (int *)param_1[1];
  if (param_1 == (int *)piVar2[2]) {
    piVar2[2] = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  *piVar2 = iVar1;
  *(int **)(iVar1 + 8) = param_1;
  param_1[1] = iVar1;
  return;
}



void __thiscall FUN_3b4012e0(void *this,int *param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = *param_1;
  *param_1 = *(int *)(iVar1 + 8);
  if (*(char *)(*(int *)(iVar1 + 8) + 0x21) == '\0') {
    *(int **)(*(int *)(iVar1 + 8) + 4) = param_1;
  }
  *(int *)(iVar1 + 4) = param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int *)(*(int *)((int)this + 4) + 4) = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  piVar2 = (int *)param_1[1];
  if (param_1 == (int *)piVar2[2]) {
    piVar2[2] = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  *piVar2 = iVar1;
  *(int **)(iVar1 + 8) = param_1;
  param_1[1] = iVar1;
  return;
}



undefined4 * __thiscall FUN_3b401350(void *this,uint *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = *(undefined4 **)((int)this + 4);
  if (*(char *)((int)(undefined4 *)puVar2[1] + 0x21) == '\0') {
    puVar1 = puVar2;
    puVar3 = (undefined4 *)puVar2[1];
    do {
      puVar2 = puVar3;
      if ((param_1[1] < (uint)puVar2[5]) ||
         ((param_1[1] <= (uint)puVar2[5] && (*param_1 <= (uint)puVar2[4])))) {
        puVar3 = (undefined4 *)*puVar2;
      }
      else {
        puVar3 = (undefined4 *)puVar2[2];
        puVar2 = puVar1;
      }
      puVar1 = puVar2;
    } while (*(char *)((int)puVar3 + 0x21) == '\0');
  }
  return puVar2;
}



void __thiscall FUN_3b4013a0(void *this,int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar1 = (int **)param_1[2];
  param_1[2] = (int)*ppiVar1;
  if (*(char *)((int)*ppiVar1 + 0x15) == '\0') {
    (*ppiVar1)[1] = (int)param_1;
  }
  ppiVar1[1] = (int *)param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar1;
    *ppiVar1 = param_1;
    param_1[1] = (int)ppiVar1;
    return;
  }
  ppiVar2 = (int **)param_1[1];
  if (param_1 == *ppiVar2) {
    *ppiVar2 = (int *)ppiVar1;
    *ppiVar1 = param_1;
    param_1[1] = (int)ppiVar1;
    return;
  }
  ppiVar2[2] = (int *)ppiVar1;
  *ppiVar1 = param_1;
  param_1[1] = (int)ppiVar1;
  return;
}



void __thiscall FUN_3b401400(void *this,int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar1 = (int **)param_1[2];
  param_1[2] = (int)*ppiVar1;
  if (*(char *)((int)*ppiVar1 + 0x21) == '\0') {
    (*ppiVar1)[1] = (int)param_1;
  }
  ppiVar1[1] = (int *)param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar1;
    *ppiVar1 = param_1;
    param_1[1] = (int)ppiVar1;
    return;
  }
  ppiVar2 = (int **)param_1[1];
  if (param_1 == *ppiVar2) {
    *ppiVar2 = (int *)ppiVar1;
    *ppiVar1 = param_1;
    param_1[1] = (int)ppiVar1;
    return;
  }
  ppiVar2[2] = (int *)ppiVar1;
  *ppiVar1 = param_1;
  param_1[1] = (int)ppiVar1;
  return;
}



void __thiscall FUN_3b401460(void *this,int **param_1,char param_2,int **param_3,int *param_4)

{
  char cVar1;
  int *piVar2;
  int **ppiVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  void *extraout_ECX;
  int *piVar7;
  int **ppiVar8;
  
  uVar5 = *(uint *)((int)this + 8);
  if (0xffffffd < uVar5) {
    FUN_3b404a3d(param_4);
    uVar5 = FUN_3b4047f6("map/set<T> too long");
    this = extraout_ECX;
  }
  *(uint *)((int)this + 8) = uVar5 + 1;
  param_4[1] = (int)param_3;
  if (param_3 == *(int ***)((int)this + 4)) {
    (*(int ***)((int)this + 4))[1] = param_4;
    **(int ***)((int)this + 4) = param_4;
    *(int **)(*(int *)((int)this + 4) + 8) = param_4;
  }
  else if (param_2 == '\0') {
    param_3[2] = param_4;
    if (param_3 == *(int ***)(*(int *)((int)this + 4) + 8)) {
      *(int **)(*(int *)((int)this + 4) + 8) = param_4;
    }
  }
  else {
    *param_3 = param_4;
    if (param_3 == (int **)**(int ***)((int)this + 4)) {
      **(int ***)((int)this + 4) = param_4;
    }
  }
  cVar1 = *(char *)(param_4[1] + 0x20);
  piVar6 = param_4;
  do {
    if (cVar1 != '\0') {
      iVar4 = *(int *)(*(int *)((int)this + 4) + 4);
      *param_1 = param_4;
      *(undefined *)(iVar4 + 0x20) = 1;
      return;
    }
    piVar7 = (int *)piVar6[1];
    ppiVar8 = (int **)piVar7[1];
    if (piVar7 == *ppiVar8) {
      piVar2 = ppiVar8[2];
      if (*(char *)(piVar2 + 8) == '\0') {
        *(undefined *)(piVar7 + 8) = 1;
        *(undefined *)(piVar2 + 8) = 1;
        *(undefined *)(*(int *)(piVar6[1] + 4) + 0x20) = 0;
        piVar6 = *(int **)(piVar6[1] + 4);
      }
      else {
        if (piVar6 == (int *)piVar7[2]) {
          ppiVar8 = (int **)piVar7[2];
          piVar7[2] = (int)*ppiVar8;
          if (*(char *)((int)*ppiVar8 + 0x21) == '\0') {
            (*ppiVar8)[1] = (int)piVar7;
          }
          ppiVar8[1] = (int *)piVar7[1];
          if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
            *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
          }
          else {
            ppiVar3 = (int **)piVar7[1];
            if (piVar7 == *ppiVar3) {
              *ppiVar3 = (int *)ppiVar8;
            }
            else {
              ppiVar3[2] = (int *)ppiVar8;
            }
          }
          *ppiVar8 = piVar7;
          piVar7[1] = (int)ppiVar8;
          piVar6 = piVar7;
        }
        *(undefined *)(piVar6[1] + 0x20) = 1;
        *(undefined *)(*(int *)(piVar6[1] + 4) + 0x20) = 0;
        piVar7 = *(int **)(piVar6[1] + 4);
        ppiVar8 = (int **)*piVar7;
        *piVar7 = (int)ppiVar8[2];
        if (*(char *)((int)ppiVar8[2] + 0x21) == '\0') {
          *(int **)((int)ppiVar8[2] + 4) = piVar7;
        }
        ppiVar8[1] = (int *)piVar7[1];
        if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
          *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
          ppiVar8[2] = piVar7;
        }
        else {
          piVar2 = (int *)piVar7[1];
          if (piVar7 == (int *)piVar2[2]) {
            piVar2[2] = (int)ppiVar8;
            ppiVar8[2] = piVar7;
          }
          else {
            *piVar2 = (int)ppiVar8;
            ppiVar8[2] = piVar7;
          }
        }
LAB_3b40165d:
        piVar7[1] = (int)ppiVar8;
      }
    }
    else {
      piVar2 = *ppiVar8;
      if (*(char *)(piVar2 + 8) != '\0') {
        if (piVar6 == (int *)*piVar7) {
          iVar4 = *piVar7;
          *piVar7 = *(int *)(iVar4 + 8);
          if (*(char *)(*(int *)(iVar4 + 8) + 0x21) == '\0') {
            *(int **)(*(int *)(iVar4 + 8) + 4) = piVar7;
          }
          *(int *)(iVar4 + 4) = piVar7[1];
          if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
            *(int *)(*(int *)((int)this + 4) + 4) = iVar4;
          }
          else {
            piVar6 = (int *)piVar7[1];
            if (piVar7 == (int *)piVar6[2]) {
              piVar6[2] = iVar4;
            }
            else {
              *piVar6 = iVar4;
            }
          }
          *(int **)(iVar4 + 8) = piVar7;
          piVar7[1] = iVar4;
          piVar6 = piVar7;
        }
        *(undefined *)(piVar6[1] + 0x20) = 1;
        *(undefined *)(*(int *)(piVar6[1] + 4) + 0x20) = 0;
        piVar7 = *(int **)(piVar6[1] + 4);
        ppiVar8 = (int **)piVar7[2];
        piVar7[2] = (int)*ppiVar8;
        if (*(char *)((int)*ppiVar8 + 0x21) == '\0') {
          (*ppiVar8)[1] = (int)piVar7;
        }
        ppiVar8[1] = (int *)piVar7[1];
        if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
          *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
        }
        else {
          ppiVar3 = (int **)piVar7[1];
          if (piVar7 == *ppiVar3) {
            *ppiVar3 = (int *)ppiVar8;
          }
          else {
            ppiVar3[2] = (int *)ppiVar8;
          }
        }
        *ppiVar8 = piVar7;
        goto LAB_3b40165d;
      }
      *(undefined *)(piVar7 + 8) = 1;
      *(undefined *)(piVar2 + 8) = 1;
      *(undefined *)(*(int *)(piVar6[1] + 4) + 0x20) = 0;
      piVar6 = *(int **)(piVar6[1] + 4);
    }
    cVar1 = *(char *)(piVar6[1] + 0x20);
  } while( true );
}



void __thiscall FUN_3b401690(void *this,int **param_1,char param_2,int **param_3,int *param_4)

{
  char cVar1;
  int *piVar2;
  int **ppiVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  void *extraout_ECX;
  int *piVar7;
  int **ppiVar8;
  
  uVar5 = *(uint *)((int)this + 8);
  if (0x1ffffffd < uVar5) {
    FUN_3b404a3d(param_4);
    uVar5 = FUN_3b4047f6("map/set<T> too long");
    this = extraout_ECX;
  }
  *(uint *)((int)this + 8) = uVar5 + 1;
  param_4[1] = (int)param_3;
  if (param_3 == *(int ***)((int)this + 4)) {
    (*(int ***)((int)this + 4))[1] = param_4;
    **(int ***)((int)this + 4) = param_4;
    *(int **)(*(int *)((int)this + 4) + 8) = param_4;
  }
  else if (param_2 == '\0') {
    param_3[2] = param_4;
    if (param_3 == *(int ***)(*(int *)((int)this + 4) + 8)) {
      *(int **)(*(int *)((int)this + 4) + 8) = param_4;
    }
  }
  else {
    *param_3 = param_4;
    if (param_3 == (int **)**(int ***)((int)this + 4)) {
      **(int ***)((int)this + 4) = param_4;
    }
  }
  cVar1 = *(char *)(param_4[1] + 0x14);
  piVar6 = param_4;
  do {
    if (cVar1 != '\0') {
      iVar4 = *(int *)(*(int *)((int)this + 4) + 4);
      *param_1 = param_4;
      *(undefined *)(iVar4 + 0x14) = 1;
      return;
    }
    piVar7 = (int *)piVar6[1];
    ppiVar8 = (int **)piVar7[1];
    if (piVar7 == *ppiVar8) {
      piVar2 = ppiVar8[2];
      if (*(char *)(piVar2 + 5) == '\0') {
        *(undefined *)(piVar7 + 5) = 1;
        *(undefined *)(piVar2 + 5) = 1;
        *(undefined *)(*(int *)(piVar6[1] + 4) + 0x14) = 0;
        piVar6 = *(int **)(piVar6[1] + 4);
      }
      else {
        if (piVar6 == (int *)piVar7[2]) {
          ppiVar8 = (int **)piVar7[2];
          piVar7[2] = (int)*ppiVar8;
          if (*(char *)((int)*ppiVar8 + 0x15) == '\0') {
            (*ppiVar8)[1] = (int)piVar7;
          }
          ppiVar8[1] = (int *)piVar7[1];
          if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
            *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
          }
          else {
            ppiVar3 = (int **)piVar7[1];
            if (piVar7 == *ppiVar3) {
              *ppiVar3 = (int *)ppiVar8;
            }
            else {
              ppiVar3[2] = (int *)ppiVar8;
            }
          }
          *ppiVar8 = piVar7;
          piVar7[1] = (int)ppiVar8;
          piVar6 = piVar7;
        }
        *(undefined *)(piVar6[1] + 0x14) = 1;
        *(undefined *)(*(int *)(piVar6[1] + 4) + 0x14) = 0;
        piVar7 = *(int **)(piVar6[1] + 4);
        ppiVar8 = (int **)*piVar7;
        *piVar7 = (int)ppiVar8[2];
        if (*(char *)((int)ppiVar8[2] + 0x15) == '\0') {
          *(int **)((int)ppiVar8[2] + 4) = piVar7;
        }
        ppiVar8[1] = (int *)piVar7[1];
        if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
          *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
          ppiVar8[2] = piVar7;
        }
        else {
          piVar2 = (int *)piVar7[1];
          if (piVar7 == (int *)piVar2[2]) {
            piVar2[2] = (int)ppiVar8;
            ppiVar8[2] = piVar7;
          }
          else {
            *piVar2 = (int)ppiVar8;
            ppiVar8[2] = piVar7;
          }
        }
LAB_3b40188d:
        piVar7[1] = (int)ppiVar8;
      }
    }
    else {
      piVar2 = *ppiVar8;
      if (*(char *)(piVar2 + 5) != '\0') {
        if (piVar6 == (int *)*piVar7) {
          iVar4 = *piVar7;
          *piVar7 = *(int *)(iVar4 + 8);
          if (*(char *)(*(int *)(iVar4 + 8) + 0x15) == '\0') {
            *(int **)(*(int *)(iVar4 + 8) + 4) = piVar7;
          }
          *(int *)(iVar4 + 4) = piVar7[1];
          if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
            *(int *)(*(int *)((int)this + 4) + 4) = iVar4;
          }
          else {
            piVar6 = (int *)piVar7[1];
            if (piVar7 == (int *)piVar6[2]) {
              piVar6[2] = iVar4;
            }
            else {
              *piVar6 = iVar4;
            }
          }
          *(int **)(iVar4 + 8) = piVar7;
          piVar7[1] = iVar4;
          piVar6 = piVar7;
        }
        *(undefined *)(piVar6[1] + 0x14) = 1;
        *(undefined *)(*(int *)(piVar6[1] + 4) + 0x14) = 0;
        piVar7 = *(int **)(piVar6[1] + 4);
        ppiVar8 = (int **)piVar7[2];
        piVar7[2] = (int)*ppiVar8;
        if (*(char *)((int)*ppiVar8 + 0x15) == '\0') {
          (*ppiVar8)[1] = (int)piVar7;
        }
        ppiVar8[1] = (int *)piVar7[1];
        if (piVar7 == *(int **)(*(int *)((int)this + 4) + 4)) {
          *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
        }
        else {
          ppiVar3 = (int **)piVar7[1];
          if (piVar7 == *ppiVar3) {
            *ppiVar3 = (int *)ppiVar8;
          }
          else {
            ppiVar3[2] = (int *)ppiVar8;
          }
        }
        *ppiVar8 = piVar7;
        goto LAB_3b40188d;
      }
      *(undefined *)(piVar7 + 5) = 1;
      *(undefined *)(piVar2 + 5) = 1;
      *(undefined *)(*(int *)(piVar6[1] + 4) + 0x14) = 0;
      piVar6 = *(int **)(piVar6[1] + 4);
    }
    cVar1 = *(char *)(piVar6[1] + 0x14);
  } while( true );
}



void __thiscall FUN_3b4018c0(void *this,int **param_1,int **param_2)

{
  undefined uVar1;
  int iVar2;
  int *piVar3;
  int **ppiVar4;
  int **ppiVar5;
  undefined4 uVar6;
  int **ppiVar7;
  int **ppiVar8;
  
  ppiVar4 = param_2;
  if (*(char *)((int)param_2 + 0x15) != '\0') {
    FUN_3b404843("invalid map/set<T> iterator");
  }
  FUN_3b4010e0((int **)&param_2);
  ppiVar7 = (int **)*ppiVar4;
  if (*(char *)((int)ppiVar7 + 0x15) == '\0') {
    ppiVar8 = ppiVar7;
    if ((*(char *)((int)ppiVar4[2] + 0x15) == '\0') &&
       (ppiVar8 = (int **)param_2[2], param_2 != ppiVar4)) {
      ppiVar7[1] = (int *)param_2;
      *param_2 = *ppiVar4;
      ppiVar7 = param_2;
      if (param_2 != (int **)ppiVar4[2]) {
        ppiVar7 = (int **)param_2[1];
        if (*(char *)((int)ppiVar8 + 0x15) == '\0') {
          ppiVar8[1] = (int *)ppiVar7;
        }
        *ppiVar7 = (int *)ppiVar8;
        param_2[2] = ppiVar4[2];
        ppiVar4[2][1] = (int)param_2;
      }
      if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar4) {
        *(int ***)(*(int *)((int)this + 4) + 4) = param_2;
      }
      else {
        piVar3 = ppiVar4[1];
        if ((int **)*piVar3 == ppiVar4) {
          *piVar3 = (int)param_2;
        }
        else {
          piVar3[2] = (int)param_2;
        }
      }
      param_2[1] = ppiVar4[1];
      uVar1 = *(undefined *)(param_2 + 5);
      *(undefined *)(param_2 + 5) = *(undefined *)(ppiVar4 + 5);
      *(undefined *)(ppiVar4 + 5) = uVar1;
      goto LAB_3b4019da;
    }
  }
  else {
    ppiVar8 = (int **)ppiVar4[2];
  }
  ppiVar7 = (int **)ppiVar4[1];
  if (*(char *)((int)ppiVar8 + 0x15) == '\0') {
    ppiVar8[1] = (int *)ppiVar7;
  }
  if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar4) {
    *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
  }
  else if ((int **)*ppiVar7 == ppiVar4) {
    *ppiVar7 = (int *)ppiVar8;
  }
  else {
    ppiVar7[2] = (int *)ppiVar8;
  }
  if ((int **)**(int **)((int)this + 4) == ppiVar4) {
    ppiVar5 = ppiVar7;
    if (*(char *)((int)ppiVar8 + 0x15) == '\0') {
      ppiVar5 = (int **)FUN_3b401080(ppiVar8);
    }
    **(int ***)((int)this + 4) = (int *)ppiVar5;
  }
  iVar2 = *(int *)((int)this + 4);
  if (*(int ***)(iVar2 + 8) == ppiVar4) {
    if (*(char *)((int)ppiVar8 + 0x15) == '\0') {
      uVar6 = FUN_3b401060((int)ppiVar8);
      *(undefined4 *)(iVar2 + 8) = uVar6;
    }
    else {
      *(int ***)(iVar2 + 8) = ppiVar7;
    }
  }
LAB_3b4019da:
  if (*(char *)(ppiVar4 + 5) == '\x01') {
    if (ppiVar8 != *(int ***)(*(int *)((int)this + 4) + 4)) {
      do {
        ppiVar5 = ppiVar7;
        if (*(char *)(ppiVar8 + 5) != '\x01') break;
        ppiVar7 = (int **)*ppiVar5;
        if (ppiVar8 == ppiVar7) {
          ppiVar7 = (int **)ppiVar5[2];
          if (*(char *)(ppiVar7 + 5) == '\0') {
            *(undefined *)(ppiVar7 + 5) = 1;
            *(undefined *)(ppiVar5 + 5) = 0;
            FUN_3b4013a0(this,(int *)ppiVar5);
            ppiVar7 = (int **)ppiVar5[2];
          }
          if (*(char *)((int)ppiVar7 + 0x15) == '\0') {
            if ((*(char *)(*ppiVar7 + 5) != '\x01') || (*(char *)(ppiVar7[2] + 5) != '\x01')) {
              if (*(char *)(ppiVar7[2] + 5) == '\x01') {
                *(undefined *)(*ppiVar7 + 5) = 1;
                *(undefined *)(ppiVar7 + 5) = 0;
                FUN_3b401280(this,(int *)ppiVar7);
                ppiVar7 = (int **)ppiVar5[2];
              }
              *(undefined *)(ppiVar7 + 5) = *(undefined *)(ppiVar5 + 5);
              *(undefined *)(ppiVar5 + 5) = 1;
              *(undefined *)(ppiVar7[2] + 5) = 1;
              FUN_3b4013a0(this,(int *)ppiVar5);
              break;
            }
LAB_3b401a98:
            *(undefined *)(ppiVar7 + 5) = 0;
          }
        }
        else {
          if (*(char *)(ppiVar7 + 5) == '\0') {
            *(undefined *)(ppiVar7 + 5) = 1;
            *(undefined *)(ppiVar5 + 5) = 0;
            FUN_3b401280(this,(int *)ppiVar5);
            ppiVar7 = (int **)*ppiVar5;
          }
          if (*(char *)((int)ppiVar7 + 0x15) == '\0') {
            if ((*(char *)(ppiVar7[2] + 5) == '\x01') && (*(char *)(*ppiVar7 + 5) == '\x01'))
            goto LAB_3b401a98;
            if (*(char *)(*ppiVar7 + 5) == '\x01') {
              *(undefined *)(ppiVar7[2] + 5) = 1;
              *(undefined *)(ppiVar7 + 5) = 0;
              FUN_3b4013a0(this,(int *)ppiVar7);
              ppiVar7 = (int **)*ppiVar5;
            }
            *(undefined *)(ppiVar7 + 5) = *(undefined *)(ppiVar5 + 5);
            *(undefined *)(ppiVar5 + 5) = 1;
            *(undefined *)(*ppiVar7 + 5) = 1;
            FUN_3b401280(this,(int *)ppiVar5);
            break;
          }
        }
        ppiVar7 = (int **)ppiVar5[1];
        ppiVar8 = ppiVar5;
      } while (ppiVar5 != *(int ***)(*(int *)((int)this + 4) + 4));
    }
    *(undefined *)(ppiVar8 + 5) = 1;
  }
  FUN_3b404a3d(ppiVar4);
  if (*(int *)((int)this + 8) != 0) {
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
  }
  *param_1 = (int *)param_2;
  return;
}



void __thiscall FUN_3b401b10(void *this,int **param_1,int **param_2)

{
  undefined uVar1;
  int iVar2;
  int *piVar3;
  int **ppiVar4;
  int **ppiVar5;
  undefined4 uVar6;
  int **ppiVar7;
  int **ppiVar8;
  
  ppiVar4 = param_2;
  if (*(char *)((int)param_2 + 0x21) != '\0') {
    FUN_3b404843("invalid map/set<T> iterator");
  }
  FUN_3b401130((int **)&param_2);
  ppiVar7 = (int **)*ppiVar4;
  if (*(char *)((int)ppiVar7 + 0x21) == '\0') {
    ppiVar8 = ppiVar7;
    if ((*(char *)((int)ppiVar4[2] + 0x21) == '\0') &&
       (ppiVar8 = (int **)param_2[2], param_2 != ppiVar4)) {
      ppiVar7[1] = (int *)param_2;
      *param_2 = *ppiVar4;
      ppiVar7 = param_2;
      if (param_2 != (int **)ppiVar4[2]) {
        ppiVar7 = (int **)param_2[1];
        if (*(char *)((int)ppiVar8 + 0x21) == '\0') {
          ppiVar8[1] = (int *)ppiVar7;
        }
        *ppiVar7 = (int *)ppiVar8;
        param_2[2] = ppiVar4[2];
        ppiVar4[2][1] = (int)param_2;
      }
      if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar4) {
        *(int ***)(*(int *)((int)this + 4) + 4) = param_2;
      }
      else {
        piVar3 = ppiVar4[1];
        if ((int **)*piVar3 == ppiVar4) {
          *piVar3 = (int)param_2;
        }
        else {
          piVar3[2] = (int)param_2;
        }
      }
      param_2[1] = ppiVar4[1];
      uVar1 = *(undefined *)(param_2 + 8);
      *(undefined *)(param_2 + 8) = *(undefined *)(ppiVar4 + 8);
      *(undefined *)(ppiVar4 + 8) = uVar1;
      goto LAB_3b401c2a;
    }
  }
  else {
    ppiVar8 = (int **)ppiVar4[2];
  }
  ppiVar7 = (int **)ppiVar4[1];
  if (*(char *)((int)ppiVar8 + 0x21) == '\0') {
    ppiVar8[1] = (int *)ppiVar7;
  }
  if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar4) {
    *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
  }
  else if ((int **)*ppiVar7 == ppiVar4) {
    *ppiVar7 = (int *)ppiVar8;
  }
  else {
    ppiVar7[2] = (int *)ppiVar8;
  }
  if ((int **)**(int **)((int)this + 4) == ppiVar4) {
    ppiVar5 = ppiVar7;
    if (*(char *)((int)ppiVar8 + 0x21) == '\0') {
      ppiVar5 = (int **)FUN_3b4010c0(ppiVar8);
    }
    **(int ***)((int)this + 4) = (int *)ppiVar5;
  }
  iVar2 = *(int *)((int)this + 4);
  if (*(int ***)(iVar2 + 8) == ppiVar4) {
    if (*(char *)((int)ppiVar8 + 0x21) == '\0') {
      uVar6 = FUN_3b4010a0((int)ppiVar8);
      *(undefined4 *)(iVar2 + 8) = uVar6;
    }
    else {
      *(int ***)(iVar2 + 8) = ppiVar7;
    }
  }
LAB_3b401c2a:
  if (*(char *)(ppiVar4 + 8) == '\x01') {
    if (ppiVar8 != *(int ***)(*(int *)((int)this + 4) + 4)) {
      do {
        ppiVar5 = ppiVar7;
        if (*(char *)(ppiVar8 + 8) != '\x01') break;
        ppiVar7 = (int **)*ppiVar5;
        if (ppiVar8 == ppiVar7) {
          ppiVar7 = (int **)ppiVar5[2];
          if (*(char *)(ppiVar7 + 8) == '\0') {
            *(undefined *)(ppiVar7 + 8) = 1;
            *(undefined *)(ppiVar5 + 8) = 0;
            FUN_3b401400(this,(int *)ppiVar5);
            ppiVar7 = (int **)ppiVar5[2];
          }
          if (*(char *)((int)ppiVar7 + 0x21) == '\0') {
            if ((*(char *)(*ppiVar7 + 8) != '\x01') || (*(char *)(ppiVar7[2] + 8) != '\x01')) {
              if (*(char *)(ppiVar7[2] + 8) == '\x01') {
                *(undefined *)(*ppiVar7 + 8) = 1;
                *(undefined *)(ppiVar7 + 8) = 0;
                FUN_3b4012e0(this,(int *)ppiVar7);
                ppiVar7 = (int **)ppiVar5[2];
              }
              *(undefined *)(ppiVar7 + 8) = *(undefined *)(ppiVar5 + 8);
              *(undefined *)(ppiVar5 + 8) = 1;
              *(undefined *)(ppiVar7[2] + 8) = 1;
              FUN_3b401400(this,(int *)ppiVar5);
              break;
            }
LAB_3b401ce8:
            *(undefined *)(ppiVar7 + 8) = 0;
          }
        }
        else {
          if (*(char *)(ppiVar7 + 8) == '\0') {
            *(undefined *)(ppiVar7 + 8) = 1;
            *(undefined *)(ppiVar5 + 8) = 0;
            FUN_3b4012e0(this,(int *)ppiVar5);
            ppiVar7 = (int **)*ppiVar5;
          }
          if (*(char *)((int)ppiVar7 + 0x21) == '\0') {
            if ((*(char *)(ppiVar7[2] + 8) == '\x01') && (*(char *)(*ppiVar7 + 8) == '\x01'))
            goto LAB_3b401ce8;
            if (*(char *)(*ppiVar7 + 8) == '\x01') {
              *(undefined *)(ppiVar7[2] + 8) = 1;
              *(undefined *)(ppiVar7 + 8) = 0;
              FUN_3b401400(this,(int *)ppiVar7);
              ppiVar7 = (int **)*ppiVar5;
            }
            *(undefined *)(ppiVar7 + 8) = *(undefined *)(ppiVar5 + 8);
            *(undefined *)(ppiVar5 + 8) = 1;
            *(undefined *)(*ppiVar7 + 8) = 1;
            FUN_3b4012e0(this,(int *)ppiVar5);
            break;
          }
        }
        ppiVar7 = (int **)ppiVar5[1];
        ppiVar8 = ppiVar5;
      } while (ppiVar5 != *(int ***)(*(int *)((int)this + 4) + 4));
    }
    *(undefined *)(ppiVar8 + 8) = 1;
  }
  FUN_3b404a3d(ppiVar4);
  if (*(int *)((int)this + 8) != 0) {
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
  }
  *param_1 = (int *)param_2;
  return;
}



void FUN_3b401d60(int *param_1)

{
  char cVar1;
  int *piVar2;
  
  cVar1 = *(char *)((int)param_1 + 0x15);
  while (cVar1 == '\0') {
    FUN_3b401d60((int *)param_1[2]);
    piVar2 = (int *)*param_1;
    FUN_3b404a3d(param_1);
    param_1 = piVar2;
    cVar1 = *(char *)((int)piVar2 + 0x15);
  }
  return;
}



void FUN_3b401da0(int *param_1)

{
  char cVar1;
  int *piVar2;
  
  cVar1 = *(char *)((int)param_1 + 0x21);
  while (cVar1 == '\0') {
    FUN_3b401da0((int *)param_1[2]);
    piVar2 = (int *)*param_1;
    FUN_3b404a3d(param_1);
    param_1 = piVar2;
    cVar1 = *(char *)((int)piVar2 + 0x21);
  }
  return;
}



void __thiscall FUN_3b401de0(void *this,undefined4 *param_1,int *param_2,char param_3)

{
  char cVar1;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  undefined4 *puVar5;
  bool local_8;
  
  ppiVar2 = (int **)(*(int ***)((int)this + 4))[1];
  cVar1 = *(char *)((int)ppiVar2 + 0x21);
  local_8 = true;
  ppiVar3 = *(int ***)((int)this + 4);
  do {
    if (cVar1 != '\0') {
      _param_3 = ppiVar3;
      if (local_8) {
        if (ppiVar3 == (int **)**(int **)((int)this + 4)) {
          puVar5 = (undefined4 *)FUN_3b401460(this,(int **)&param_3,'\x01',ppiVar3,param_2);
          *param_1 = *puVar5;
          *(undefined *)(param_1 + 1) = 1;
          return;
        }
        FUN_3b4011a0((int **)&param_3);
      }
      ppiVar2 = _param_3;
      if ((_param_3[5] <= (int *)param_2[5]) &&
         ((_param_3[5] < (int *)param_2[5] || (_param_3[4] < (int *)param_2[4])))) {
        puVar5 = (undefined4 *)FUN_3b401460(this,(int **)&param_3,local_8,ppiVar3,param_2);
        *param_1 = *puVar5;
        *(undefined *)(param_1 + 1) = 1;
        return;
      }
      FUN_3b404a3d(param_2);
      *param_1 = ppiVar2;
      *(undefined *)(param_1 + 1) = 0;
      return;
    }
    if (param_3 == '\0') {
      if ((ppiVar2[5] < (int *)param_2[5]) ||
         ((ppiVar2[5] <= (int *)param_2[5] && (ppiVar2[4] <= (int *)param_2[4])))) {
        local_8 = false;
        goto LAB_3b401e53;
      }
      ppiVar4 = (int **)*ppiVar2;
      local_8 = true;
    }
    else {
      if (((int *)param_2[5] < ppiVar2[5]) ||
         (((int *)param_2[5] <= ppiVar2[5] && ((int *)param_2[4] <= ppiVar2[4])))) {
        local_8 = false;
      }
      else {
        local_8 = true;
      }
      local_8 = !local_8;
      if (local_8) {
        ppiVar4 = (int **)*ppiVar2;
      }
      else {
LAB_3b401e53:
        ppiVar4 = (int **)ppiVar2[2];
      }
    }
    cVar1 = *(char *)((int)ppiVar4 + 0x21);
    ppiVar3 = ppiVar2;
    ppiVar2 = ppiVar4;
  } while( true );
}



void __thiscall FUN_3b401ef0(void *this,undefined4 *param_1,int *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)((int)this + 4);
  if (*(char *)((int)(undefined4 *)puVar3[1] + 0x15) == '\0') {
    puVar1 = (undefined4 *)puVar3[1];
    do {
      if ((int)puVar1[3] < *param_2) {
        puVar2 = (undefined4 *)puVar1[2];
      }
      else {
        puVar2 = (undefined4 *)*puVar1;
        puVar3 = puVar1;
      }
      puVar1 = puVar2;
    } while (*(char *)((int)puVar2 + 0x15) == '\0');
  }
  if ((puVar3 != *(undefined4 **)((int)this + 4)) && ((int)puVar3[3] <= *param_2)) {
    *param_1 = puVar3;
    return;
  }
  *param_1 = *(undefined4 **)((int)this + 4);
  return;
}



void __fastcall FUN_3b401f60(int param_1)

{
  char cVar1;
  int *piVar2;
  int *piVar3;
  
  piVar2 = *(int **)(*(int *)(param_1 + 4) + 4);
  cVar1 = *(char *)((int)piVar2 + 0x15);
  while (cVar1 == '\0') {
    FUN_3b401d60((int *)piVar2[2]);
    piVar3 = (int *)*piVar2;
    FUN_3b404a3d(piVar2);
    piVar2 = piVar3;
    cVar1 = *(char *)((int)piVar3 + 0x15);
  }
  *(int *)(*(int *)(param_1 + 4) + 4) = *(int *)(param_1 + 4);
  *(undefined4 *)*(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 4);
  *(int *)(*(int *)(param_1 + 4) + 8) = *(int *)(param_1 + 4);
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



void __fastcall FUN_3b401fb0(int param_1)

{
  char cVar1;
  int *piVar2;
  int *piVar3;
  
  piVar2 = *(int **)(*(int *)(param_1 + 4) + 4);
  cVar1 = *(char *)((int)piVar2 + 0x21);
  while (cVar1 == '\0') {
    FUN_3b401da0((int *)piVar2[2]);
    piVar3 = (int *)*piVar2;
    FUN_3b404a3d(piVar2);
    piVar2 = piVar3;
    cVar1 = *(char *)((int)piVar3 + 0x21);
  }
  *(int *)(*(int *)(param_1 + 4) + 4) = *(int *)(param_1 + 4);
  *(undefined4 *)*(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 4);
  *(int *)(*(int *)(param_1 + 4) + 8) = *(int *)(param_1 + 4);
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



void __thiscall FUN_3b402000(void *this,int param_1,byte param_2)

{
  char cVar1;
  int iVar2;
  int **ppiVar3;
  int iVar4;
  int **ppiVar5;
  undefined4 *puVar6;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_20;
  void *local_1c;
  undefined4 local_18;
  undefined *local_14;
  undefined4 local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_3b410bd0;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_10;
  local_14 = &stack0xffffffd4;
  local_18 = local_18 & 0xffffff00;
  local_1c = this;
  puVar6 = (undefined4 *)FUN_3b401ef0(this,&local_20,(int *)(param_1 + 4));
  *(undefined4 *)((int)this + 0x10) = *puVar6;
  while ((iVar2 = *(int *)((int)this + 0x10), iVar2 != *(int *)((int)this + 4) &&
         (*(int *)(iVar2 + 0xc) == *(int *)(param_1 + 4)))) {
    if (*(char *)(iVar2 + 0x15) == '\0') {
      ppiVar3 = *(int ***)(iVar2 + 8);
      if (*(char *)((int)ppiVar3 + 0x15) == '\0') {
        cVar1 = *(char *)((int)*ppiVar3 + 0x15);
        ppiVar5 = (int **)*ppiVar3;
        while (cVar1 == '\0') {
          cVar1 = *(char *)((int)*ppiVar5 + 0x15);
          ppiVar3 = ppiVar5;
          ppiVar5 = (int **)*ppiVar5;
        }
        *(int ***)((int)this + 0x10) = ppiVar3;
      }
      else {
        iVar4 = *(int *)(iVar2 + 4);
        cVar1 = *(char *)(iVar4 + 0x15);
        while ((cVar1 == '\0' && (*(int *)((int)this + 0x10) == *(int *)(iVar4 + 8)))) {
          *(int *)((int)this + 0x10) = iVar4;
          iVar4 = *(int *)(iVar4 + 4);
          cVar1 = *(char *)(iVar4 + 0x15);
        }
        *(int *)((int)this + 0x10) = iVar4;
      }
    }
    if (param_2 == (*(byte *)(*(int **)(iVar2 + 0x10) + 1) >> 1 & 1)) {
      local_8 = 0;
      local_18 = CONCAT31(local_18._1_3_,1);
      (**(code **)(**(int **)(iVar2 + 0x10) + 4))(*(undefined4 *)(param_1 + 8));
      local_8 = 0xffffffff;
    }
  }
  *(undefined4 *)((int)this + 0x10) = *(undefined4 *)((int)this + 4);
  if (*(code **)((int)this + 0x28) != (code *)0x0) {
    (**(code **)((int)this + 0x28))(param_1,local_18);
  }
  *unaff_FS_OFFSET = local_10;
  return;
}



void __thiscall FUN_3b402120(void *this,int param_1,byte param_2)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int **ppiVar4;
  int iVar5;
  int **ppiVar6;
  int iVar7;
  int *piVar8;
  undefined4 local_8;
  
  iVar7 = param_1;
  piVar1 = (int *)(param_1 + 4);
  local_8 = (uint)this & 0xffffff00;
  piVar8 = (int *)FUN_3b401ef0(this,&param_1,piVar1);
  iVar3 = *piVar8;
  *(int *)((int)this + 0x10) = iVar3;
  if (iVar3 != *(int *)((int)this + 4)) {
    do {
      iVar3 = *(int *)((int)this + 0x10);
      if (*(int *)(iVar3 + 0xc) != *piVar1) break;
      if (*(char *)(iVar3 + 0x15) == '\0') {
        ppiVar4 = *(int ***)(iVar3 + 8);
        if (*(char *)((int)ppiVar4 + 0x15) == '\0') {
          cVar2 = *(char *)((int)*ppiVar4 + 0x15);
          ppiVar6 = (int **)*ppiVar4;
          while (cVar2 == '\0') {
            cVar2 = *(char *)((int)*ppiVar6 + 0x15);
            ppiVar4 = ppiVar6;
            ppiVar6 = (int **)*ppiVar6;
          }
          *(int ***)((int)this + 0x10) = ppiVar4;
        }
        else {
          iVar5 = *(int *)(iVar3 + 4);
          cVar2 = *(char *)(iVar5 + 0x15);
          while ((cVar2 == '\0' && (*(int *)((int)this + 0x10) == *(int *)(iVar5 + 8)))) {
            *(int *)((int)this + 0x10) = iVar5;
            iVar5 = *(int *)(iVar5 + 4);
            cVar2 = *(char *)(iVar5 + 0x15);
          }
          *(int *)((int)this + 0x10) = iVar5;
        }
      }
      if (param_2 == (*(byte *)(*(int **)(iVar3 + 0x10) + 1) >> 1 & 1)) {
        local_8 = CONCAT31(local_8._1_3_,1);
        (**(code **)(**(int **)(iVar3 + 0x10) + 4))(*(undefined4 *)(iVar7 + 8));
      }
    } while (*(int *)((int)this + 0x10) != *(int *)((int)this + 4));
  }
  *(undefined4 *)((int)this + 0x10) = *(undefined4 *)((int)this + 4);
  if (*(code **)((int)this + 0x28) != (code *)0x0) {
    (**(code **)((int)this + 0x28))(iVar7,local_8);
  }
  return;
}



void __thiscall FUN_3b4021f0(void *this,int **param_1)

{
  int **ppiVar1;
  char cVar2;
  int **ppiVar3;
  int **ppiVar4;
  int **ppiVar5;
  int **ppiVar6;
  
  ppiVar4 = param_1;
  if ((*(byte *)(param_1 + 1) & 1) != 0) {
    *(byte *)(param_1 + 1) = *(byte *)(param_1 + 1) & 0xfe;
    ppiVar1 = param_1 + 2;
    FUN_3b401ef0(this,&param_1,(int *)ppiVar1);
    if (param_1 != *(int ***)((int)this + 4)) {
      ppiVar6 = param_1;
      while (ppiVar6[3] == *ppiVar1) {
        if ((int **)ppiVar6[4] == ppiVar4) {
          if (*(int ***)((int)this + 0x10) == ppiVar6) {
            FUN_3b4010e0((int **)((int)this + 0x10));
          }
          FUN_3b4018c0(this,(int **)&param_1,ppiVar6);
          return;
        }
        if (*(char *)((int)ppiVar6 + 0x15) == '\0') {
          ppiVar3 = (int **)ppiVar6[2];
          if (*(char *)((int)ppiVar3 + 0x15) == '\0') {
            cVar2 = *(char *)((int)*ppiVar3 + 0x15);
            ppiVar6 = ppiVar3;
            ppiVar3 = (int **)*ppiVar3;
            while (cVar2 == '\0') {
              cVar2 = *(char *)((int)*ppiVar3 + 0x15);
              ppiVar6 = ppiVar3;
              ppiVar3 = (int **)*ppiVar3;
            }
          }
          else {
            cVar2 = *(char *)((int)ppiVar6[1] + 0x15);
            ppiVar5 = (int **)ppiVar6[1];
            ppiVar3 = ppiVar6;
            while ((ppiVar6 = ppiVar5, cVar2 == '\0' && (ppiVar3 == (int **)ppiVar6[2]))) {
              cVar2 = *(char *)((int)ppiVar6[1] + 0x15);
              ppiVar5 = (int **)ppiVar6[1];
              ppiVar3 = ppiVar6;
            }
          }
        }
        if (ppiVar6 == *(int ***)((int)this + 4)) {
          return;
        }
      }
    }
  }
  return;
}



void __thiscall FUN_3b4022b0(void *this,int **param_1)

{
  int **ppiVar1;
  char cVar2;
  int ***pppiVar3;
  size_t _Size;
  int *local_14;
  int local_10;
  int **local_c;
  void *local_8;
  
  ppiVar1 = param_1;
  local_14 = (int *)((int)this + 0x54);
  param_1 = (int **)FUN_3b401350(local_14,(uint *)param_1);
  if (param_1 != *(int ***)((int)this + 0x58)) {
    if ((param_1[5] <= ppiVar1[1]) && ((param_1[5] < ppiVar1[1] || (param_1[4] <= *ppiVar1)))) {
      pppiVar3 = &param_1;
      goto LAB_3b4022f2;
    }
  }
  local_c = *(int ***)((int)this + 0x58);
  pppiVar3 = &local_c;
LAB_3b4022f2:
  local_c = *pppiVar3;
  if (local_c != *(int ***)((int)this + 0x58)) {
    local_10 = local_c[6][2];
    _Size = (**(code **)(*local_c[6] + 8))();
    local_8 = _malloc(_Size);
    param_1 = (int **)((uint)param_1 & 0xffffff00);
    cVar2 = (**(code **)((int)this + 0x1c))
                      (*(undefined4 *)((int)this + 0x24),*ppiVar1,ppiVar1[1],local_8,_Size,local_10,
                       &param_1);
    if (cVar2 != '\0') {
      (**(code **)*local_c[6])(local_8,param_1,*ppiVar1,ppiVar1[1]);
    }
    _free(local_8);
    FUN_3b401b10(local_14,&local_14,local_c);
  }
  return;
}



void __thiscall FUN_3b402380(void *this,int **param_1,int **param_2,int **param_3)

{
  char cVar1;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  int *local_8;
  
  local_8 = (int *)this;
  if ((param_2 == (int **)**(int ***)((int)this + 4)) && (param_3 == *(int ***)((int)this + 4))) {
    FUN_3b401f60((int)this);
    *param_1 = **(int ***)((int)this + 4);
    return;
  }
  if (param_2 != param_3) {
    do {
      ppiVar3 = param_2;
      if (*(char *)((int)param_2 + 0x15) == '\0') {
        ppiVar2 = (int **)param_2[2];
        if (*(char *)((int)ppiVar2 + 0x15) == '\0') {
          cVar1 = *(char *)((int)*ppiVar2 + 0x15);
          param_2 = ppiVar2;
          ppiVar2 = (int **)*ppiVar2;
          while (cVar1 == '\0') {
            cVar1 = *(char *)((int)*ppiVar2 + 0x15);
            param_2 = ppiVar2;
            ppiVar2 = (int **)*ppiVar2;
          }
        }
        else {
          cVar1 = *(char *)((int)param_2[1] + 0x15);
          ppiVar4 = (int **)param_2[1];
          ppiVar2 = param_2;
          while ((param_2 = ppiVar4, cVar1 == '\0' && (ppiVar2 == (int **)param_2[2]))) {
            cVar1 = *(char *)((int)param_2[1] + 0x15);
            ppiVar4 = (int **)param_2[1];
            ppiVar2 = param_2;
          }
        }
      }
      FUN_3b4018c0(this,&local_8,ppiVar3);
    } while (param_2 != param_3);
  }
  *param_1 = (int *)param_2;
  return;
}



void __thiscall FUN_3b402420(void *this,int **param_1,int **param_2,int **param_3)

{
  char cVar1;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  int *local_8;
  
  local_8 = (int *)this;
  if ((param_2 == (int **)**(int ***)((int)this + 4)) && (param_3 == *(int ***)((int)this + 4))) {
    FUN_3b401fb0((int)this);
    *param_1 = **(int ***)((int)this + 4);
    return;
  }
  if (param_2 != param_3) {
    do {
      ppiVar3 = param_2;
      if (*(char *)((int)param_2 + 0x21) == '\0') {
        ppiVar2 = (int **)param_2[2];
        if (*(char *)((int)ppiVar2 + 0x21) == '\0') {
          cVar1 = *(char *)((int)*ppiVar2 + 0x21);
          param_2 = ppiVar2;
          ppiVar2 = (int **)*ppiVar2;
          while (cVar1 == '\0') {
            cVar1 = *(char *)((int)*ppiVar2 + 0x21);
            param_2 = ppiVar2;
            ppiVar2 = (int **)*ppiVar2;
          }
        }
        else {
          cVar1 = *(char *)((int)param_2[1] + 0x21);
          ppiVar4 = (int **)param_2[1];
          ppiVar2 = param_2;
          while ((param_2 = ppiVar4, cVar1 == '\0' && (ppiVar2 == (int **)param_2[2]))) {
            cVar1 = *(char *)((int)param_2[1] + 0x21);
            ppiVar4 = (int **)param_2[1];
            ppiVar2 = param_2;
          }
        }
      }
      FUN_3b401b10(this,&local_8,ppiVar3);
    } while (param_2 != param_3);
  }
  *param_1 = (int *)param_2;
  return;
}



void __thiscall FUN_3b4024c0(void *this,undefined4 *param_1)

{
  code *pcVar1;
  undefined4 *puVar2;
  undefined **local_10 [3];
  
  puVar2 = (undefined4 *)operator_new(0x28);
  if (puVar2 != (undefined4 *)0x0) {
    *puVar2 = *(undefined4 *)((int)this + 4);
    puVar2[1] = *(undefined4 *)((int)this + 4);
    puVar2[2] = *(undefined4 *)((int)this + 4);
    *(undefined2 *)(puVar2 + 8) = 0;
    if (puVar2 + 4 != (undefined4 *)0x0) {
      puVar2[4] = *param_1;
      puVar2[5] = param_1[1];
      puVar2[6] = param_1[2];
    }
    return;
  }
  param_1 = (undefined4 *)0x0;
  std::exception::exception((exception *)local_10,(char **)&param_1);
  local_10[0] = &PTR_FUN_3b4111a0;
  __CxxThrowException_8(local_10,&DAT_3b413dc0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void __thiscall FUN_3b402540(void *this,undefined4 *param_1)

{
  code *pcVar1;
  undefined4 *puVar2;
  undefined **local_10 [3];
  
  puVar2 = (undefined4 *)operator_new(0x18);
  if (puVar2 != (undefined4 *)0x0) {
    *puVar2 = *(undefined4 *)((int)this + 4);
    puVar2[1] = *(undefined4 *)((int)this + 4);
    puVar2[2] = *(undefined4 *)((int)this + 4);
    *(undefined2 *)(puVar2 + 5) = 0;
    if (puVar2 + 3 != (undefined4 *)0x0) {
      puVar2[3] = *param_1;
      puVar2[4] = param_1[1];
    }
    return;
  }
  param_1 = (undefined4 *)0x0;
  std::exception::exception((exception *)local_10,(char **)&param_1);
  local_10[0] = &PTR_FUN_3b4111a0;
  __CxxThrowException_8(local_10,&DAT_3b413dc0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void __thiscall FUN_3b4025b0(void *this,HMODULE param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = GetProcAddress(param_1,"Steam_BGetCallback");
  *(FARPROC *)((int)this + 0x14) = pFVar1;
  pFVar1 = GetProcAddress(param_1,"Steam_FreeLastCallback");
  *(FARPROC *)((int)this + 0x18) = pFVar1;
  pFVar1 = GetProcAddress(param_1,"Steam_GetAPICallResult");
  *(FARPROC *)((int)this + 0x1c) = pFVar1;
  if ((*(byte *)((int)this + 0x30) & 1) != 0) {
    SteamAPI_UnregisterCallback((int **)((int)this + 0x2c));
  }
  *(void **)((int)this + 0x38) = this;
  *(code **)((int)this + 0x3c) = FUN_3b4022b0;
  SteamAPI_RegisterCallback((int)(int **)((int)this + 0x2c),0x2bf);
  if ((*(byte *)((int)this + 0x44) & 1) != 0) {
    SteamAPI_UnregisterCallback((int **)((int)this + 0x40));
  }
  *(byte *)((int)this + 0x44) = *(byte *)((int)this + 0x44) | 2;
  *(void **)((int)this + 0x4c) = this;
  *(code **)((int)this + 0x50) = FUN_3b4022b0;
  SteamAPI_RegisterCallback((int)(int **)((int)this + 0x40),0x2bf);
  return;
}



void __thiscall FUN_3b402650(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  char cVar2;
  bool bVar3;
  undefined4 local_14 [4];
  
  uVar1 = param_1;
  if (((*(int *)((int)this + 0x14) != 0) && (*(int *)((int)this + 0x18) != 0)) &&
     (DAT_3b417081 == '\0')) {
    DAT_3b417081 = 1;
    *(undefined4 *)((int)this + 0x24) = param_1;
    while (*(code **)((int)this + 0x14) != (code *)0x0) {
      cVar2 = (**(code **)((int)this + 0x14))(uVar1,local_14,&param_1);
      if (cVar2 == '\0') break;
      bVar3 = DAT_3b416008 == '\0';
      *(undefined4 *)((int)this + 0x20) = local_14[0];
      if (bVar3) {
        FUN_3b402120(this,(int)local_14,(byte)param_2);
      }
      else {
        FUN_3b402000(this,(int)local_14,(byte)param_2);
      }
      if (*(code **)((int)this + 0x18) != (code *)0x0) {
        (**(code **)((int)this + 0x18))(uVar1);
      }
    }
    *(undefined4 *)((int)this + 0x24) = 0;
    DAT_3b417081 = '\0';
  }
  return;
}



void __thiscall FUN_3b402700(void *this,undefined4 *param_1,int *param_2)

{
  int *piVar1;
  undefined4 *puVar2;
  int **ppiVar3;
  int **ppiVar4;
  
  piVar1 = (int *)FUN_3b402540(this,param_2);
  ppiVar4 = *(int ***)((int)this + 4);
  param_2 = (int *)CONCAT31(param_2._1_3_,1);
  if (*(char *)((int)ppiVar4[1] + 0x15) == '\0') {
    ppiVar3 = (int **)ppiVar4[1];
    do {
      ppiVar4 = ppiVar3;
      param_2 = (int *)CONCAT31(param_2._1_3_,piVar1[3] < (int)ppiVar4[3]);
      if (piVar1[3] < (int)ppiVar4[3]) {
        ppiVar3 = (int **)*ppiVar4;
      }
      else {
        ppiVar3 = (int **)ppiVar4[2];
      }
    } while (*(char *)((int)ppiVar3 + 0x15) == '\0');
  }
  puVar2 = (undefined4 *)FUN_3b401690(this,&param_2,(char)param_2,ppiVar4,piVar1);
  *param_1 = *puVar2;
  *(undefined *)(param_1 + 1) = 1;
  return;
}



void __fastcall FUN_3b402770(void *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  int *local_18;
  void *local_14;
  undefined4 local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_3b410be8;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_10;
  local_8 = 0;
  local_14 = param_1;
  FUN_3b402380(param_1,&local_18,(int **)**(int ***)((int)param_1 + 4),*(int ***)((int)param_1 + 4))
  ;
  FUN_3b404a3d(*(void **)((int)param_1 + 4));
  *unaff_FS_OFFSET = local_10;
  return;
}



int __fastcall FUN_3b4027d0(int param_1)

{
  code *pcVar1;
  void *pvVar2;
  int iVar3;
  undefined4 *unaff_FS_OFFSET;
  undefined **local_34 [3];
  undefined **local_28 [3];
  int local_1c;
  char *local_18;
  char *local_14;
  undefined4 local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_3b410c1e;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_10;
  *(undefined4 *)(param_1 + 8) = 0;
  local_1c = param_1;
  pvVar2 = operator_new(0x18);
  if (pvVar2 != (void *)0x0) {
    *(void **)(param_1 + 4) = pvVar2;
    *(void **)pvVar2 = pvVar2;
    *(int *)(*(int *)(param_1 + 4) + 4) = *(int *)(param_1 + 4);
    *(int *)(*(int *)(param_1 + 4) + 8) = *(int *)(param_1 + 4);
    *(undefined *)(*(int *)(param_1 + 4) + 0x14) = 1;
    *(undefined *)(*(int *)(param_1 + 4) + 0x15) = 1;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined *)(param_1 + 0x30) = 0;
    *(undefined4 *)(param_1 + 0x34) = 0;
    *(undefined ***)(param_1 + 0x2c) = &PTR_FUN_3b4111ac;
    *(undefined4 *)(param_1 + 0x38) = 0;
    *(undefined4 *)(param_1 + 0x3c) = 0;
    *(undefined *)(param_1 + 0x44) = 0;
    *(undefined4 *)(param_1 + 0x48) = 0;
    *(undefined ***)(param_1 + 0x40) = &PTR_FUN_3b4111bc;
    *(undefined4 *)(param_1 + 0x4c) = 0;
    *(undefined4 *)(param_1 + 0x50) = 0;
    local_8 = 2;
    *(undefined4 *)(param_1 + 0x5c) = 0;
    pvVar2 = operator_new(0x28);
    if (pvVar2 != (void *)0x0) {
      *(void **)(param_1 + 0x58) = pvVar2;
      *(void **)pvVar2 = pvVar2;
      *(int *)(*(int *)(param_1 + 0x58) + 4) = *(int *)(param_1 + 0x58);
      *(int *)(*(int *)(param_1 + 0x58) + 8) = *(int *)(param_1 + 0x58);
      *(undefined *)(*(int *)(param_1 + 0x58) + 0x20) = 1;
      *(undefined *)(*(int *)(param_1 + 0x58) + 0x21) = 1;
      *(undefined4 *)(param_1 + 0x14) = 0;
      *(undefined4 *)(param_1 + 0x18) = 0;
      *(undefined4 *)(param_1 + 0x1c) = 0;
      *(undefined4 *)(param_1 + 0x28) = 0;
      *(undefined4 *)(param_1 + 0x24) = 0;
      *(undefined4 *)(param_1 + 0x20) = 0;
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 4);
      DAT_3b417080 = 1;
      *unaff_FS_OFFSET = local_10;
      return param_1;
    }
    local_14 = (char *)0x0;
    std::exception::exception((exception *)local_28,&local_14);
    local_28[0] = &PTR_FUN_3b4111a0;
    __CxxThrowException_8(local_28,&DAT_3b413dc0);
  }
  local_18 = (char *)0x0;
  std::exception::exception((exception *)local_34,&local_18);
  local_34[0] = &PTR_FUN_3b4111a0;
  __CxxThrowException_8(local_34,&DAT_3b413dc0);
  pcVar1 = (code *)swi(3);
  iVar3 = (*pcVar1)();
  return iVar3;
}



void __fastcall FUN_3b402910(void *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  int *local_1c;
  void *local_18;
  void *local_14;
  undefined4 local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_3b410c5e;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_10;
  local_18 = (void *)((int)param_1 + 0x54);
  DAT_3b417080 = 0;
  local_8 = 3;
  local_14 = param_1;
  FUN_3b402420(local_18,&local_1c,(int **)**(int ***)((int)param_1 + 0x58),
               *(int ***)((int)param_1 + 0x58));
  FUN_3b404a3d(*(void **)((int)param_1 + 0x58));
  *(int **)((int)param_1 + 0x40) = (int *)&PTR_FUN_3b4111bc;
  if ((*(byte *)((int)param_1 + 0x44) & 1) != 0) {
    SteamAPI_UnregisterCallback((int **)((int)param_1 + 0x40));
  }
  *(int **)((int)param_1 + 0x2c) = (int *)&PTR_FUN_3b4111ac;
  if ((*(byte *)((int)param_1 + 0x30) & 1) != 0) {
    SteamAPI_UnregisterCallback((int **)((int)param_1 + 0x2c));
  }
  local_8 = 4;
  FUN_3b402380(param_1,&local_1c,(int **)**(int ***)((int)param_1 + 4),*(int ***)((int)param_1 + 4))
  ;
  FUN_3b404a3d(*(void **)((int)param_1 + 4));
  *unaff_FS_OFFSET = local_10;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_3b4029d0(void)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_10 = *unaff_FS_OFFSET;
  puStack_c = &LAB_3b410c7e;
  *unaff_FS_OFFSET = &local_10;
  if ((_DAT_3b4170ec & 1) == 0) {
    _DAT_3b4170ec = _DAT_3b4170ec | 1;
    local_8 = 0;
    FUN_3b4027d0(0x3b417088);
    _atexit((_func_4879 *)&LAB_3b410cb0);
  }
  *unaff_FS_OFFSET = local_10;
  return &DAT_3b417088;
}



void __cdecl FUN_3b402a30(int param_1,int param_2)

{
  undefined *this;
  undefined4 local_14 [2];
  int local_c;
  int local_8;
  
  this = FUN_3b4029d0();
  *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 1;
  *(int *)(param_1 + 8) = param_2;
  local_c = param_2;
  local_8 = param_1;
  FUN_3b402700(this,local_14,&local_c);
  return;
}



void __cdecl FUN_3b402a70(int **param_1)

{
  undefined *this;
  
  if (DAT_3b417080 != '\0') {
    this = FUN_3b4029d0();
    FUN_3b4021f0(this,param_1);
  }
  return;
}



void __cdecl FUN_3b402a90(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined *puVar1;
  int *piVar2;
  char cVar3;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_14 = param_2;
  local_10 = param_3;
  local_c = param_1;
  puVar1 = FUN_3b4029d0();
  cVar3 = '\0';
  piVar2 = (int *)FUN_3b4024c0(puVar1 + 0x54,&local_14);
  FUN_3b401de0(puVar1 + 0x54,&param_2,piVar2,cVar3);
  return;
}



void __cdecl FUN_3b402ad0(undefined4 param_1,int *param_2,int **param_3)

{
  int **ppiVar1;
  undefined *puVar2;
  int ***pppiVar3;
  int *local_10;
  int **local_c;
  int **local_8;
  
  if (DAT_3b417080 != '\0') {
    local_10 = param_2;
    local_c = param_3;
    puVar2 = FUN_3b4029d0();
    local_8 = (int **)FUN_3b401350(puVar2 + 0x54,(uint *)&local_10);
    ppiVar1 = *(int ***)(puVar2 + 0x58);
    if (((local_8 == ppiVar1) || (param_3 < local_8[5])) ||
       ((param_3 <= local_8[5] && (param_2 < local_8[4])))) {
      local_c = ppiVar1;
      pppiVar3 = &local_c;
    }
    else {
      pppiVar3 = &local_8;
    }
    if (*pppiVar3 != ppiVar1) {
      FUN_3b401b10(puVar2 + 0x54,(int **)&local_c,*pppiVar3);
    }
  }
  return;
}



void __cdecl FUN_3b402b40(undefined4 param_1,undefined4 param_2)

{
  undefined *this;
  
  this = FUN_3b4029d0();
  FUN_3b402650(this,param_1,param_2);
  return;
}



void __cdecl FUN_3b402b60(HMODULE param_1)

{
  undefined *this;
  
  this = FUN_3b4029d0();
  FUN_3b4025b0(this,param_1);
  return;
}



undefined4 FUN_3b402b80(void)

{
  undefined *puVar1;
  
  puVar1 = FUN_3b4029d0();
  return *(undefined4 *)(puVar1 + 0x20);
}



undefined4 SteamClient(void)

{
                    // 0x2b90  22  SteamClient
  return DAT_3b417158;
}



undefined4 SteamUser(void)

{
                    // 0x2ba0  50  SteamUser
  return DAT_3b417290;
}



undefined4 SteamFriends(void)

{
                    // 0x2bb0  28  SteamFriends
  return DAT_3b417294;
}



undefined4 SteamUtils(void)

{
                    // 0x2bc0  52  SteamUtils
  return DAT_3b417298;
}



undefined4 SteamMatchmaking(void)

{
                    // 0x2bd0  45  SteamMatchmaking
  return DAT_3b41729c;
}



undefined4 SteamMatchmakingServers(void)

{
                    // 0x2be0  46  SteamMatchmakingServers
  return DAT_3b4172a8;
}



undefined4 SteamUserStats(void)

{
                    // 0x2bf0  51  SteamUserStats
  return DAT_3b4172a0;
}



undefined4 SteamApps(void)

{
                    // 0x2c00  21  SteamApps
  return DAT_3b4172a4;
}



undefined4 SteamNetworking(void)

{
                    // 0x2c10  47  SteamNetworking
  return DAT_3b4172ac;
}



undefined4 SteamRemoteStorage(void)

{
                    // 0x2c20  48  SteamRemoteStorage
  return DAT_3b4172b0;
}



undefined4 SteamScreenshots(void)

{
                    // 0x2c30  49  SteamScreenshots
  return DAT_3b4172b4;
}



undefined4 SteamHTTP(void)

{
                    // 0x2c40  44  SteamHTTP
  return DAT_3b4172b8;
}



undefined4 GetHSteamPipe(void)

{
                    // 0x2c50  1  GetHSteamPipe
                    // 0x2c50  3  SteamAPI_GetHSteamPipe
  return DAT_3b417160;
}



HMODULE __cdecl FUN_3b402c60(LPCSTR param_1)

{
  char cVar1;
  longlong lVar2;
  LPCSTR pCVar3;
  int cbMultiByte;
  LPCWSTR lpWideCharStr;
  int iVar4;
  HMODULE pHVar5;
  
  pCVar3 = param_1;
  do {
    cVar1 = *pCVar3;
    pCVar3 = pCVar3 + 1;
  } while (cVar1 != '\0');
  cbMultiByte = (int)pCVar3 - (int)(param_1 + 1);
  lVar2 = (ulonglong)(cbMultiByte + 1U) * 2;
  lpWideCharStr = (LPCWSTR)operator_new(-(uint)((int)((ulonglong)lVar2 >> 0x20) != 0) | (uint)lVar2)
  ;
  *lpWideCharStr = L'\0';
  iVar4 = MultiByteToWideChar(0xfde9,0,param_1,cbMultiByte,lpWideCharStr,cbMultiByte + 1U);
  if (iVar4 != 0) {
    if (iVar4 < cbMultiByte) {
      cbMultiByte = iVar4;
    }
    lpWideCharStr[cbMultiByte] = L'\0';
    pHVar5 = LoadLibraryExW(lpWideCharStr,(HANDLE)0x0,8);
    if (pHVar5 != (HMODULE)0x0) goto LAB_3b402ce4;
  }
  pHVar5 = LoadLibraryExA(param_1,(HANDLE)0x0,8);
LAB_3b402ce4:
  FUN_3b404a3d(lpWideCharStr);
  return pHVar5;
}



undefined4 FUN_3b402d00(void)

{
  char *in_EAX;
  FILE *_File;
  undefined4 uVar1;
  char local_104;
  undefined local_103 [254];
  undefined local_5;
  
  uVar1 = 0;
  _File = _fopen(in_EAX,"rb");
  if (_File != (FILE *)0x0) {
    local_104 = '\0';
    _memset(local_103,0,0xff);
    _fgets(&local_104,0x100,_File);
    local_5 = 0;
    uVar1 = FUN_3b4051f7(&local_104);
    _fclose(_File);
  }
  return uVar1;
}



undefined4 FUN_3b402d70(void)

{
  int iVar1;
  char *unaff_ESI;
  
  iVar1 = __stricmp(unaff_ESI,"HKEY_LOCAL_MACHINE");
  if (iVar1 != 0) {
    iVar1 = __stricmp(unaff_ESI,"HKLM");
    if (iVar1 != 0) {
      iVar1 = __stricmp(unaff_ESI,"HKEY_CURRENT_USER");
      if (iVar1 != 0) {
        iVar1 = __stricmp(unaff_ESI,"HKCU");
        if (iVar1 != 0) {
          iVar1 = __stricmp(unaff_ESI,"HKEY_CLASSES_ROOT");
          if (iVar1 != 0) {
            iVar1 = __stricmp(unaff_ESI,"HKCR");
            if (iVar1 != 0) {
              return 0;
            }
          }
          return 0x80000000;
        }
      }
      return 0x80000001;
    }
  }
  return 0x80000002;
}



bool __cdecl FUN_3b402e00(LPCSTR param_1,LPCSTR param_2,LPBYTE param_3)

{
  HKEY hKey;
  LSTATUS LVar1;
  DWORD local_c;
  HKEY local_8;
  
  hKey = (HKEY)FUN_3b402d70();
  local_8 = (HKEY)0x0;
  LVar1 = RegOpenKeyExA(hKey,param_1,0,0x20019,&local_8);
  if (LVar1 == 0) {
    LVar1 = RegQueryValueExA(local_8,param_2,(LPDWORD)0x0,&local_c,param_3,(LPDWORD)&stack0x00000010
                            );
    RegCloseKey(local_8);
  }
  return LVar1 == 0;
}



void __cdecl FUN_3b402e70(char *param_1)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = param_1;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  pcVar2 = pcVar2 + (-1 - (int)(param_1 + 1));
  if (0 < (int)pcVar2) {
    do {
      if ((param_1[(int)pcVar2] == '\\') || (param_1[(int)pcVar2] == '/')) break;
      pcVar2 = pcVar2 + -1;
    } while (0 < (int)pcVar2);
    param_1[(int)pcVar2] = '\0';
  }
  return;
}



undefined4 __cdecl FUN_3b402eb0(char *param_1,size_t param_2)

{
  BYTE BVar1;
  char *pcVar2;
  HKEY hKey;
  LSTATUS LVar3;
  BYTE *pBVar4;
  HMODULE hModule;
  char *pcVar5;
  DWORD nSize;
  BYTE local_118 [260];
  DWORD local_14;
  DWORD local_10;
  HKEY local_c;
  undefined local_5;
  
  pcVar2 = &DAT_3b417168;
  do {
    pcVar5 = pcVar2;
    pcVar2 = pcVar5 + 1;
  } while (*pcVar5 != '\0');
  if ((pcVar5 + -0x3b417168 != (char *)0x0) && (param_1 == (char *)0x0)) {
    return CONCAT31((int3)((uint)(pcVar5 + -0x3b417168) >> 8),1);
  }
  local_118[0] = '\0';
  _memset(local_118 + 1,0,0x103);
  local_10 = 0x104;
  hKey = (HKEY)FUN_3b402d70();
  local_c = (HKEY)0x0;
  LVar3 = RegOpenKeyExA(hKey,"Software\\Valve\\Steam\\ActiveProcess",0,0x20019,&local_c);
  local_5 = LVar3 == 0;
  if ((bool)local_5) {
    LVar3 = RegQueryValueExA(local_c,"SteamClientDll",(LPDWORD)0x0,&local_14,local_118,&local_10);
    RegCloseKey(local_c);
    local_5 = LVar3 == 0;
  }
  pBVar4 = local_118;
  do {
    BVar1 = *pBVar4;
    pBVar4 = pBVar4 + 1;
  } while (BVar1 != '\0');
  if (pBVar4 == local_118 + 1) {
    nSize = 0x104;
    pBVar4 = local_118;
    hModule = GetModuleHandleA(PTR_s_steamclient_dll_3b4160f8);
    GetModuleFileNameA(hModule,(LPSTR)pBVar4,nSize);
  }
  if (param_1 != (char *)0x0) {
    _strncpy(param_1,(char *)local_118,param_2);
  }
  _strncpy(&DAT_3b417168,(char *)local_118,0x104);
  pcVar2 = &DAT_3b417168;
  do {
    pcVar5 = pcVar2;
    pcVar2 = pcVar5 + 1;
  } while (*pcVar5 != '\0');
  pcVar5 = pcVar5 + -0x3b417169;
  if (0 < (int)pcVar5) {
    do {
      if ((pcVar5[0x3b417168] == '\\') || (pcVar5[0x3b417168] == '/')) break;
      pcVar5 = pcVar5 + -1;
    } while (0 < (int)pcVar5);
    pcVar5[0x3b417168] = '\0';
  }
  return CONCAT31((int3)((uint)pcVar5 >> 8),local_5);
}



bool __cdecl SteamAPI_RestartAppIfNecessary(int param_1)

{
  int iVar1;
  BYTE BVar2;
  char cVar3;
  bool bVar4;
  DWORD DVar5;
  int iVar6;
  BYTE *pBVar7;
  LPSTR pCVar8;
  char *pcVar9;
  HINSTANCE pHVar10;
  BYTE local_128 [260];
  CHAR local_24 [32];
  
                    // 0x3010  11  SteamAPI_RestartAppIfNecessary
  if ((param_1 != 0) &&
     (((DVar5 = GetEnvironmentVariableA("SteamAppId",local_24,0x20), 0x1e < DVar5 - 1 ||
       (iVar6 = FUN_3b4051f7(local_24), iVar6 == 0)) && (iVar6 = FUN_3b402d00(), iVar6 == 0)))) {
    local_128[0] = '\0';
    _memset(local_128 + 1,0,0x103);
    bVar4 = FUN_3b402e00("Software\\Valve\\Steam","InstallPath",local_128);
    if (bVar4) {
      pBVar7 = local_128;
      do {
        BVar2 = *pBVar7;
        pBVar7 = pBVar7 + 1;
      } while (BVar2 != '\0');
      _strncat((char *)local_128,"\\steam.exe",0x103 - ((int)pBVar7 - (int)(local_128 + 1)));
      __snprintf(&stack0xfffffad8,0x400,"-applaunch %u",param_1);
      pCVar8 = GetCommandLineA();
      if ((pCVar8 != (LPSTR)0x0) && (*pCVar8 != '\0')) {
        iVar6 = 0;
        if (*pCVar8 == '\"') {
          iVar6 = 1;
          cVar3 = pCVar8[1];
          while ((cVar3 != '\0' && (cVar3 != '\"'))) {
            iVar1 = iVar6 + 1;
            iVar6 = iVar6 + 1;
            cVar3 = pCVar8[iVar1];
          }
          if (pCVar8[iVar6] != '\0') {
            iVar6 = iVar6 + 1;
          }
        }
        cVar3 = pCVar8[iVar6];
        while ((cVar3 != '\0' && (cVar3 != ' '))) {
          iVar1 = iVar6 + 1;
          iVar6 = iVar6 + 1;
          cVar3 = pCVar8[iVar1];
        }
        if (pCVar8[iVar6] == ' ') {
          pcVar9 = &stack0xfffffad8;
          do {
            cVar3 = *pcVar9;
            pcVar9 = pcVar9 + 1;
          } while (cVar3 != '\0');
          _strncat(&stack0xfffffad8,pCVar8 + iVar6,0x3ff - ((int)pcVar9 - (int)&stack0xfffffad9));
        }
      }
      pHVar10 = ShellExecuteA((HWND)0x0,(LPCSTR)0x0,(LPCSTR)local_128,&stack0xfffffad8,(LPCSTR)0x0,1
                             );
      return (HINSTANCE)0x20 < pHVar10;
    }
  }
  return false;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_3b4031a0(void)

{
  BYTE BVar1;
  char *pcVar2;
  HKEY hKey;
  LSTATUS LVar3;
  BYTE *pBVar4;
  HMODULE hModule;
  char *pcVar5;
  DWORD nSize;
  char local_218 [8];
  undefined4 uStack_210;
  BYTE local_114 [260];
  DWORD local_10;
  DWORD local_c;
  HKEY local_8;
  
  _DAT_3b41726c = GetModuleHandleA(PTR_s_gameoverlayrenderer_dll_3b416108);
  if (_DAT_3b41726c == (HMODULE)0x0) {
    pcVar2 = &DAT_3b417168;
    do {
      pcVar5 = pcVar2;
      pcVar2 = pcVar5 + 1;
    } while (*pcVar5 != '\0');
    if (pcVar5 == &DAT_3b417168) {
      local_114[0] = '\0';
      _memset(local_114 + 1,0,0x103);
      local_c = 0x104;
      hKey = (HKEY)FUN_3b402d70();
      local_8 = (HKEY)0x0;
      LVar3 = RegOpenKeyExA(hKey,"Software\\Valve\\Steam\\ActiveProcess",0,0x20019,&local_8);
      if (LVar3 == 0) {
        RegQueryValueExA(local_8,"SteamClientDll",(LPDWORD)0x0,&local_10,local_114,&local_c);
        RegCloseKey(local_8);
      }
      pBVar4 = local_114;
      do {
        BVar1 = *pBVar4;
        pBVar4 = pBVar4 + 1;
      } while (BVar1 != '\0');
      if (pBVar4 == local_114 + 1) {
        nSize = 0x104;
        pBVar4 = local_114;
        hModule = GetModuleHandleA(PTR_s_steamclient_dll_3b4160f8);
        GetModuleFileNameA(hModule,(LPSTR)pBVar4,nSize);
      }
      _strncpy(&DAT_3b417168,(char *)local_114,0x104);
      pcVar2 = &DAT_3b417168;
      do {
        pcVar5 = pcVar2;
        pcVar2 = pcVar5 + 1;
      } while (*pcVar5 != '\0');
      pcVar5 = pcVar5 + -0x3b417169;
      if (0 < (int)pcVar5) {
        do {
          if ((pcVar5[0x3b417168] == '\\') || (pcVar5[0x3b417168] == '/')) break;
          pcVar5 = pcVar5 + -1;
        } while (0 < (int)pcVar5);
        pcVar5[0x3b417168] = '\0';
      }
    }
    __snprintf(local_218,0x104,"%s\\%s",&DAT_3b417168,PTR_s_gameoverlayrenderer_dll_3b416108);
    _DAT_3b41726c = FUN_3b402c60(local_218);
    if (_DAT_3b41726c == (HMODULE)0x0) {
      uStack_210 = 0x3b403322;
      _DAT_3b41726c = FUN_3b402c60(PTR_s_gameoverlayrenderer_dll_3b416108);
      if (_DAT_3b41726c == (HMODULE)0x0) {
        return 0;
      }
    }
  }
  return CONCAT31((int3)((uint)_DAT_3b41726c >> 8),1);
}



void __cdecl FUN_3b403340(undefined4 param_1,undefined4 param_2)

{
  undefined *puVar1;
  undefined **ppuVar2;
  char *pcVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  puVar1 = &DAT_3b411430;
  if (DAT_3b417278 == (code *)0x0) {
    puVar1 = &DAT_3b41142c;
  }
  pcVar3 = "Steam_SetMinidumpSteamID:  Caching Steam ID:  %lld [API loaded %s]\n";
  uVar4 = param_1;
  uVar5 = param_2;
  ppuVar2 = FUN_3b405a71();
  _fprintf((FILE *)(ppuVar2 + 0x10),pcVar3,uVar4,uVar5,puVar1);
  DAT_3b417150 = param_1;
  DAT_3b417154 = param_2;
  if (((DAT_3b4170f0 != '\0') && (DAT_3b416120 != 0)) && (DAT_3b417278 != (code *)0x0)) {
    pcVar3 = "Steam_SetMinidumpSteamID:  Setting Steam ID:  %lld\n";
    uVar4 = param_1;
    uVar5 = param_2;
    ppuVar2 = FUN_3b405a71();
    _fprintf((FILE *)(ppuVar2 + 0x10),pcVar3,uVar4,uVar5);
    (*DAT_3b417278)(param_1,param_2);
  }
  return;
}



void FUN_3b4033d0(void)

{
  DAT_3b417270 = 0;
  DAT_3b417274 = 0;
  if (DAT_3b4170f0 == '\0') {
    if (DAT_3b416118 != '\0') {
      DAT_3b416118 = '\0';
      if (DAT_3b416114 != (HMODULE)0x0) {
        FreeLibrary(DAT_3b416114);
        DAT_3b416114 = (HMODULE)0x0;
      }
    }
  }
  else if (DAT_3b416124 != '\0') {
    DAT_3b416124 = '\0';
    if (DAT_3b416120 != (HMODULE)0x0) {
      FreeLibrary(DAT_3b416120);
      DAT_3b416120 = (HMODULE)0x0;
      return;
    }
  }
  return;
}



uint SteamAPI_IsSteamRunning(void)

{
  HKEY hKey;
  LSTATUS LVar1;
  HANDLE hProcess;
  uint uVar2;
  BOOL BVar3;
  undefined uVar4;
  DWORD local_18;
  DWORD local_14;
  DWORD local_10;
  DWORD local_c;
  HKEY local_8;
  
                    // 0x3440  8  SteamAPI_IsSteamRunning
  hKey = (HKEY)FUN_3b402d70();
  uVar4 = 0;
  local_8 = (HKEY)0x0;
  local_c = 0;
  LVar1 = RegOpenKeyExA(hKey,"Software\\Valve\\Steam\\ActiveProcess",0,0x20019,&local_8);
  if (LVar1 == 0) {
    local_14 = 4;
    RegQueryValueExA(local_8,(LPCSTR)&lpValueName_3b411434,(LPDWORD)0x0,&local_18,(LPBYTE)&local_c,
                     &local_14);
    RegCloseKey(local_8);
  }
  hProcess = OpenProcess(0x400,0,local_c);
  uVar2 = (uint)hProcess & 0xffffff00;
  local_10 = 0;
  if (hProcess != (HANDLE)0x0) {
    BVar3 = GetExitCodeProcess(hProcess,&local_10);
    if ((BVar3 != 0) && (local_10 == 0x103)) {
      uVar4 = 1;
    }
    BVar3 = CloseHandle(hProcess);
    uVar2 = CONCAT31((int3)((uint)BVar3 >> 8),uVar4);
  }
  return uVar2;
}



void __cdecl Steam_RunCallbacks(undefined4 param_1,undefined4 param_2)

{
                    // 0x34f0  55  Steam_RunCallbacks
  FUN_3b402b40(param_1,param_2);
  return;
}



void SteamAPI_RunCallbacks(void)

{
                    // 0x3500  12  SteamAPI_RunCallbacks
  if (DAT_3b417160 != 0) {
    FUN_3b402b40(DAT_3b417160,0);
  }
  if (DAT_3b417158 == (int *)0x0) {
    return;
  }
  if (DAT_3b41728c == (int *)0x0) {
    DAT_3b41728c = (int *)(**(code **)(*DAT_3b417158 + 0x24))(DAT_3b417160,"SteamUtils005");
    (**(code **)(*DAT_3b41728c + 0x24))();
    if (DAT_3b41728c == (int *)0x0) {
      return;
    }
  }
                    // WARNING: Could not recover jumptable at 0x3b40355c. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*DAT_3b41728c + 0x38))();
  return;
}



void __cdecl SteamAPI_RegisterCallback(int param_1,int param_2)

{
                    // 0x3560  10  SteamAPI_RegisterCallback
  FUN_3b402a30(param_1,param_2);
  return;
}



void __cdecl SteamAPI_UnregisterCallback(int **param_1)

{
                    // 0x3570  18  SteamAPI_UnregisterCallback
  FUN_3b402a70(param_1);
  return;
}



void __cdecl SteamAPI_RegisterCallResult(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
                    // 0x3580  9  SteamAPI_RegisterCallResult
  FUN_3b402a90(param_1,param_2,param_3);
  return;
}



void __cdecl SteamAPI_UnregisterCallResult(undefined4 param_1,int *param_2,int **param_3)

{
                    // 0x35a0  17  SteamAPI_UnregisterCallResult
  FUN_3b402ad0(param_1,param_2,param_3);
  return;
}



void __cdecl Steam_RegisterInterfaceFuncs(HMODULE param_1)

{
                    // 0x35c0  54  Steam_RegisterInterfaceFuncs
  FUN_3b402b60(param_1);
  return;
}



undefined4 Steam_GetHSteamUserCurrent(void)

{
  undefined *puVar1;
  
  puVar1 = FUN_3b4029d0();
  return *(undefined4 *)(puVar1 + 0x20);
                    // 0x35d0  53  Steam_GetHSteamUserCurrent
}



void __cdecl
SteamAPI_UseBreakpadCrashHandler
          (char *param_1,char *param_2,char *param_3,undefined param_4,undefined4 param_5,
          undefined4 param_6)

{
  undefined **ppuVar1;
  int iVar2;
  int param3;
  int param4;
  char **ppcVar3;
  char *_Format;
  char *local_40 [4];
  undefined *local_30;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  undefined *local_18;
  undefined *local_14;
  int local_10;
  int local_c;
  int local_8;
  
                    // 0x35e0  19  SteamAPI_UseBreakpadCrashHandler
  _Format = "Using breakpad crash handler\n";
  ppuVar1 = FUN_3b405a71();
  _fprintf((FILE *)(ppuVar1 + 0x10),_Format);
  DAT_3b4170f0 = 1;
  DAT_3b4170f1 = param_4;
  _strncpy(&DAT_3b4170f2,param_1,0x40);
  DAT_3b417131 = 0;
  DAT_3b417148 = param_5;
  DAT_3b41714c = param_6;
  local_40[0] = "Jan";
  local_40[1] = &DAT_3b41149c;
  local_40[2] = &DAT_3b411498;
  local_40[3] = &DAT_3b411494;
  local_30 = &DAT_3b411490;
  local_2c = &DAT_3b41148c;
  local_28 = &DAT_3b411488;
  local_24 = &DAT_3b411484;
  local_20 = &DAT_3b411480;
  local_1c = &DAT_3b41147c;
  local_18 = &DAT_3b411478;
  local_14 = &DAT_3b411474;
  param4 = 1;
  ppcVar3 = local_40;
  do {
    iVar2 = __strnicmp(param_2,*ppcVar3,3);
    if (iVar2 == 0) break;
    param4 = param4 + 1;
    ppcVar3 = ppcVar3 + 1;
  } while (param4 < 0xd);
  iVar2 = FUN_3b4051f7(param_2 + 4);
  param3 = FUN_3b4051f7(param_2 + 7);
  local_10 = 0;
  local_c = 0;
  local_8 = 0;
  FID_conflict__sscanf(param_3,"%02d:%02d:%02d",&local_10,&local_c,&local_8);
  __snprintf(&DAT_3b417138,0xf,"%04d%02d%02d%02d%02d%02d",param3,param4,iVar2,local_10,local_c,
             local_8);
  return;
}



undefined1 * SteamAPI_GetSteamInstallPath(void)

{
  char cVar1;
  bool bVar2;
  LSTATUS LVar3;
  HANDLE hProcess;
  BOOL BVar4;
  char *pcVar5;
  DWORD local_14;
  DWORD local_10;
  HKEY local_c;
  DWORD local_8;
  
                    // 0x3720  5  SteamAPI_GetSteamInstallPath
  lpData_3b4172c0 = 0;
  local_10 = RegOpenKeyExA((HKEY)0x80000001,"Software\\Valve\\Steam\\ActiveProcess",0,0x20019,
                           &local_c);
  if (local_10 == 0) {
    local_8 = 4;
    LVar3 = RegQueryValueExA(local_c,(LPCSTR)&lpValueName_3b411434,(LPDWORD)0x0,(LPDWORD)0x0,
                             (LPBYTE)&local_10,&local_8);
    if ((LVar3 == 0) && (hProcess = OpenProcess(0x400,0,local_10), hProcess != (HANDLE)0x0)) {
      local_14 = 0;
      BVar4 = GetExitCodeProcess(hProcess,&local_14);
      if ((BVar4 == 0) || (local_14 != 0x103)) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      CloseHandle(hProcess);
      if (bVar2) {
        local_8 = 0x104;
        LVar3 = RegQueryValueExA(local_c,"SteamClientDll",(LPDWORD)0x0,(LPDWORD)0x0,&lpData_3b4172c0
                                 ,&local_8);
        if ((LVar3 == 0) && (local_8 != 0)) {
          pcVar5 = &lpData_3b4172c0;
          do {
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          if (pcVar5 != &DAT_3b4172c1) {
            FUN_3b402e70(&lpData_3b4172c0);
            RegCloseKey(local_c);
            return &lpData_3b4172c0;
          }
        }
        lpData_3b4172c0 = 0;
      }
    }
    RegCloseKey(local_c);
  }
  return &lpData_3b4172c0;
}



bool __fastcall FUN_3b403850(int *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = DAT_3b417164;
  uVar1 = DAT_3b417160;
  if (DAT_3b417158 == (int *)0x0) {
    return false;
  }
  iVar3 = (**(code **)(*DAT_3b417158 + 0x14))(DAT_3b417164,DAT_3b417160,"SteamUser016");
  *param_1 = iVar3;
  if (iVar3 != 0) {
    iVar3 = (**(code **)(*DAT_3b417158 + 0x20))(uVar2,uVar1,"SteamFriends013");
    param_1[1] = iVar3;
    if (iVar3 != 0) {
      iVar3 = (**(code **)(*DAT_3b417158 + 0x24))(uVar1,"SteamUtils005");
      param_1[2] = iVar3;
      if (iVar3 != 0) {
        iVar3 = (**(code **)(*DAT_3b417158 + 0x28))(uVar2,uVar1,"SteamMatchMaking009");
        param_1[3] = iVar3;
        if (iVar3 != 0) {
          iVar3 = (**(code **)(*DAT_3b417158 + 0x2c))(uVar2,uVar1,"SteamMatchMakingServers002");
          param_1[6] = iVar3;
          if (iVar3 != 0) {
            iVar3 = (**(code **)(*DAT_3b417158 + 0x34))
                              (uVar2,uVar1,"STEAMUSERSTATS_INTERFACE_VERSION011");
            param_1[4] = iVar3;
            if (iVar3 != 0) {
              iVar3 = (**(code **)(*DAT_3b417158 + 0x3c))
                                (uVar2,uVar1,"STEAMAPPS_INTERFACE_VERSION005");
              param_1[5] = iVar3;
              if (iVar3 != 0) {
                iVar3 = (**(code **)(*DAT_3b417158 + 0x40))(uVar2,uVar1,"SteamNetworking005");
                param_1[7] = iVar3;
                if (iVar3 != 0) {
                  iVar3 = (**(code **)(*DAT_3b417158 + 0x44))
                                    (uVar2,uVar1,"STEAMREMOTESTORAGE_INTERFACE_VERSION010");
                  param_1[8] = iVar3;
                  if (iVar3 != 0) {
                    iVar3 = (**(code **)(*DAT_3b417158 + 0x48))
                                      (uVar2,uVar1,"STEAMSCREENSHOTS_INTERFACE_VERSION001");
                    param_1[9] = iVar3;
                    if (iVar3 != 0) {
                      iVar3 = (**(code **)(*DAT_3b417158 + 0x5c))
                                        (uVar2,uVar1,"STEAMHTTP_INTERFACE_VERSION002");
                      param_1[10] = iVar3;
                      return iVar3 != 0;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return false;
}



undefined4 GetHSteamUser(void)

{
                    // 0x39b0  2  GetHSteamUser
                    // 0x39b0  4  SteamAPI_GetHSteamUser
  return DAT_3b417164;
}



void __fastcall FUN_3b4039c0(LPCSTR *param_1)

{
  BYTE BVar1;
  char cVar2;
  HMODULE pHVar3;
  char *pcVar4;
  HKEY hKey;
  LSTATUS LVar5;
  BYTE *pBVar6;
  char *pcVar7;
  DWORD nSize;
  BYTE local_118 [259];
  undefined local_15;
  DWORD local_14;
  DWORD local_10;
  HKEY local_c;
  char local_5;
  
  param_1[1] = (LPCSTR)0x0;
  pHVar3 = GetModuleHandleA(*param_1);
  param_1[1] = (LPCSTR)pHVar3;
  pcVar4 = &DAT_3b417168;
  do {
    cVar2 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar2 != '\0');
  if (pcVar4 == &DAT_3b417169) {
    local_118[0] = '\0';
    _memset(local_118 + 1,0,0x103);
    local_10 = 0x104;
    hKey = (HKEY)FUN_3b402d70();
    local_c = (HKEY)0x0;
    LVar5 = RegOpenKeyExA(hKey,"Software\\Valve\\Steam\\ActiveProcess",0,0x20019,&local_c);
    local_5 = LVar5 == 0;
    if ((bool)local_5) {
      LVar5 = RegQueryValueExA(local_c,"SteamClientDll",(LPDWORD)0x0,&local_14,local_118,&local_10);
      RegCloseKey(local_c);
      local_5 = LVar5 == 0;
    }
    pBVar6 = local_118;
    do {
      BVar1 = *pBVar6;
      pBVar6 = pBVar6 + 1;
    } while (BVar1 != '\0');
    if (pBVar6 == local_118 + 1) {
      nSize = 0x104;
      pBVar6 = local_118;
      pHVar3 = GetModuleHandleA(PTR_s_steamclient_dll_3b4160f8);
      GetModuleFileNameA(pHVar3,(LPSTR)pBVar6,nSize);
    }
    _strncpy(&DAT_3b417168,(char *)local_118,0x104);
    pcVar4 = &DAT_3b417168;
    do {
      pcVar7 = pcVar4;
      pcVar4 = pcVar7 + 1;
    } while (*pcVar7 != '\0');
    pcVar7 = pcVar7 + -0x3b417169;
    cVar2 = local_5;
    if (0 < (int)pcVar7) {
      do {
        if ((pcVar7[0x3b417168] == '\\') || (pcVar7[0x3b417168] == '/')) break;
        pcVar7 = pcVar7 + -1;
      } while (0 < (int)pcVar7);
      pcVar7[0x3b417168] = '\0';
    }
  }
  else {
    cVar2 = '\x01';
  }
  if (param_1[1] == (LPCSTR)0x0) {
    if (cVar2 != '\0') {
      *(undefined *)(param_1 + 2) = 1;
      __snprintf((char *)local_118,0x104,"%s%c%s",&DAT_3b417168,'\\',*param_1);
      local_15 = 0;
      pHVar3 = FUN_3b402c60((LPCSTR)local_118);
      param_1[1] = (LPCSTR)pHVar3;
    }
    if (param_1[1] == (LPCSTR)0x0) {
      pHVar3 = FUN_3b402c60(*param_1);
      param_1[1] = (LPCSTR)pHVar3;
    }
  }
  return;
}



int __cdecl FUN_3b403b60(HMODULE *param_1,char param_2)

{
  undefined4 uVar1;
  HMODULE pHVar2;
  int iVar3;
  FARPROC pFVar4;
  char *param3;
  undefined4 ***local_508 [255];
  undefined local_109;
  char local_108;
  undefined local_107 [259];
  
  if (param_1 == (HMODULE *)0x0) {
    return 0;
  }
  DAT_3b417168 = 0;
  DAT_3b41728c = 0;
  local_108 = '\0';
  _memset(local_107,0,0x103);
  uVar1 = FUN_3b402eb0(&local_108,0x104);
  if ((char)uVar1 != '\0') {
    uVar1 = SteamAPI_IsSteamRunning();
    if ((char)uVar1 == '\0') {
      param3 = "[S_API FAIL] SteamAPI_Init() failed; SteamAPI_IsSteamRunning() failed.\n";
    }
    else {
      pHVar2 = FUN_3b402c60(&local_108);
      *param_1 = pHVar2;
      if (pHVar2 != (HMODULE)0x0) goto LAB_3b403c40;
      param3 = &local_108;
      __snprintf((char *)local_508,0x400,
                 "[S_API FAIL] SteamAPI_Init() failed; Sys_LoadModule failed to load: %s\n",param3);
      local_508[0] = local_508;
      local_109 = 0;
    }
    OutputDebugStringA(param3);
  }
  if (*param_1 == (HMODULE)0x0) {
    if (param_2 != '\0') {
      pHVar2 = FUN_3b402c60(PTR_s_steamclient_dll_3b4160f8);
      *param_1 = pHVar2;
    }
    if (*param_1 == (HMODULE)0x0) {
      OutputDebugStringA(
                        "[S_API FAIL] SteamAPI_Init() failed; unable to locate a running instance of Steam, or a local steamclient.dll.\n"
                        );
      return 0;
    }
  }
LAB_3b403c40:
  if (*param_1 == (HMODULE)0x0) {
    iVar3 = (*(code *)0x0)("SteamClient012",0);
    return iVar3;
  }
  pFVar4 = GetProcAddress(*param_1,"CreateInterface");
  iVar3 = (*pFVar4)("SteamClient012",0);
  return iVar3;
}



void __cdecl FUN_3b403c80(HMODULE param_1)

{
  if (param_1 != (HMODULE)0x0) {
    FreeLibrary(param_1);
  }
  FUN_3b4033d0();
  return;
}



void FUN_3b403ca0(void)

{
  undefined **ppuVar1;
  FARPROC UNRECOVERED_JUMPTABLE;
  char *pcVar2;
  
  if (DAT_3b4170f0 == '\0') {
    FUN_3b4039c0(&PTR_s_steam_dll_3b416110);
    if (DAT_3b416114 != (HMODULE)0x0) {
      DAT_3b417270 = GetProcAddress(DAT_3b416114,"SteamWriteMiniDumpUsingExceptionInfoWithBuildId");
      if (DAT_3b416114 == (HMODULE)0x0) {
        DAT_3b417274 = (FARPROC)0x0;
      }
      else {
        DAT_3b417274 = GetProcAddress(DAT_3b416114,"SteamWriteMiniDumpSetComment");
      }
      DAT_3b417278 = (FARPROC)0x0;
      if (DAT_3b416114 != (HMODULE)0x0) {
        UNRECOVERED_JUMPTABLE = GetProcAddress(DAT_3b416114,"SteamMiniDumpInit");
        if (UNRECOVERED_JUMPTABLE != (FARPROC)0x0) {
                    // WARNING: Could not recover jumptable at 0x3b403e21. Too many branches
                    // WARNING: Treating indirect jump as call
          (*UNRECOVERED_JUMPTABLE)();
          return;
        }
      }
    }
  }
  else {
    FUN_3b4039c0(&PTR_s_steamclient_dll_3b41611c);
    if (DAT_3b416120 != (HMODULE)0x0) {
      pcVar2 = "Looking up breakpad interfaces from steamclient\n";
      ppuVar1 = FUN_3b405a71();
      _fprintf((FILE *)(ppuVar1 + 0x10),pcVar2);
      if (DAT_3b416120 == (HMODULE)0x0) {
        DAT_3b417270 = (FARPROC)0x0;
      }
      else {
        DAT_3b417270 = GetProcAddress(DAT_3b416120,
                                      "Breakpad_SteamWriteMiniDumpUsingExceptionInfoWithBuildId");
      }
      if (DAT_3b416120 == (HMODULE)0x0) {
        DAT_3b417274 = (FARPROC)0x0;
      }
      else {
        DAT_3b417274 = GetProcAddress(DAT_3b416120,"Breakpad_SteamWriteMiniDumpSetComment");
      }
      if (DAT_3b416120 == (HMODULE)0x0) {
        DAT_3b417278 = (FARPROC)0x0;
      }
      else {
        DAT_3b417278 = GetProcAddress(DAT_3b416120,"Breakpad_SteamSetSteamID");
      }
      if (DAT_3b416120 == (HMODULE)0x0) {
        DAT_3b41727c = (FARPROC)0x0;
      }
      else {
        DAT_3b41727c = GetProcAddress(DAT_3b416120,"Breakpad_SteamSetAppID");
      }
      if (DAT_3b416120 != (HMODULE)0x0) {
        UNRECOVERED_JUMPTABLE = GetProcAddress(DAT_3b416120,"Breakpad_SteamMiniDumpInit");
        if (UNRECOVERED_JUMPTABLE != (FARPROC)0x0) {
          pcVar2 = "Calling BreakpadMiniDumpSystemInit\n";
          ppuVar1 = FUN_3b405a71();
          _fprintf((FILE *)(ppuVar1 + 0x10),pcVar2);
          (*UNRECOVERED_JUMPTABLE)
                    (DAT_3b417134,&DAT_3b4170f2,&DAT_3b417138,(uint)DAT_3b4170f1,DAT_3b417148,
                     DAT_3b41714c);
          if ((DAT_3b417150 | DAT_3b417154) != 0) {
            FUN_3b403340(DAT_3b417150,DAT_3b417154);
          }
        }
      }
    }
  }
  return;
}



void SteamAPI_Shutdown(void)

{
                    // 0x3e30  16  SteamAPI_Shutdown
  DAT_3b41728c = 0;
  if ((DAT_3b417160 != 0) && (DAT_3b417164 != 0)) {
    (**(code **)(*DAT_3b417158 + 0x10))(DAT_3b417160,DAT_3b417164);
  }
  DAT_3b417164 = 0;
  DAT_3b417290 = 0;
  DAT_3b417294 = 0;
  DAT_3b417298 = 0;
  DAT_3b41729c = 0;
  DAT_3b4172a0 = 0;
  DAT_3b4172a4 = 0;
  DAT_3b4172a8 = 0;
  DAT_3b4172ac = 0;
  DAT_3b4172b0 = 0;
  DAT_3b4172b8 = 0;
  DAT_3b4172b4 = 0;
  if (DAT_3b417160 != 0) {
    (**(code **)(*DAT_3b417158 + 4))(DAT_3b417160);
  }
  DAT_3b417160 = 0;
  if (DAT_3b417158 != (int *)0x0) {
    (**(code **)(*DAT_3b417158 + 0x58))();
  }
  DAT_3b417158 = (int *)0x0;
  if (DAT_3b41715c != (HMODULE)0x0) {
    FreeLibrary(DAT_3b41715c);
    FUN_3b4033d0();
  }
  DAT_3b41715c = (HMODULE)0x0;
  return;
}



void SteamAPI_WriteMiniDump(void)

{
                    // 0x3f00  20  SteamAPI_WriteMiniDump
  if (DAT_3b417270 == (code *)0x0) {
    FUN_3b403ca0();
    if (DAT_3b417270 == (code *)0x0) {
      return;
    }
  }
                    // WARNING: Could not recover jumptable at 0x3b403f1b. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_3b417270)();
  return;
}



void SteamAPI_SetMiniDumpComment(void)

{
                    // 0x3f20  14  SteamAPI_SetMiniDumpComment
  if (DAT_3b417274 == (code *)0x0) {
    FUN_3b403ca0();
    if (DAT_3b417274 == (code *)0x0) {
      return;
    }
  }
                    // WARNING: Could not recover jumptable at 0x3b403f3b. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_3b417274)();
  return;
}



void __cdecl SteamAPI_SetBreakpadAppID(int param_1)

{
  undefined **ppuVar1;
  char *pcVar2;
  int iVar3;
  
                    // 0x3f40  13  SteamAPI_SetBreakpadAppID
  if (DAT_3b417134 != param_1) {
    pcVar2 = "Setting breakpad minidump AppID = %u\n";
    iVar3 = param_1;
    ppuVar1 = FUN_3b405a71();
    _fprintf((FILE *)(ppuVar1 + 0x10),pcVar2,iVar3);
    DAT_3b417134 = param_1;
  }
  if (((param_1 != 0) && (DAT_3b417270 == 0)) && (DAT_3b4170f0 != '\0')) {
    pcVar2 = "Forcing breakpad minidump interfaces to load\n";
    ppuVar1 = FUN_3b405a71();
    _fprintf((FILE *)(ppuVar1 + 0x10),pcVar2);
    FUN_3b403ca0();
  }
  if (DAT_3b41727c != (code *)0x0) {
    (*DAT_3b41727c)(DAT_3b417134);
  }
  return;
}



undefined4 __cdecl FUN_3b403fd0(char param_1)

{
  bool bVar1;
  undefined4 in_EAX;
  int *piVar2;
  uint uVar3;
  DWORD DVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  int iVar7;
  char local_10 [4];
  undefined4 local_c;
  undefined local_5;
  
  if (DAT_3b417158 != (int *)0x0) {
    return CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  piVar2 = (int *)FUN_3b403b60(&DAT_3b41715c,'\0');
  DAT_3b417158 = piVar2;
  if (piVar2 == (int *)0x0) {
LAB_3b4041cf:
    return (uint)piVar2 & 0xffffff00;
  }
  DAT_3b417160 = (**(code **)*piVar2)();
  DAT_3b417164 = (**(code **)(*DAT_3b417158 + 8))(DAT_3b417160);
  DAT_3b41728c = 0;
  if ((DAT_3b417160 == 0) || (DAT_3b417164 == 0)) {
    piVar2 = (int *)SteamAPI_Shutdown();
    goto LAB_3b4041cf;
  }
  if (param_1 == '\0') {
    bVar1 = FUN_3b403850((int *)&DAT_3b417290);
    if (!bVar1) goto LAB_3b40408e;
    iVar7 = *DAT_3b417298;
LAB_3b404078:
    uVar3 = (**(code **)(iVar7 + 0x24))();
    if (uVar3 != 0) {
      DVar4 = GetEnvironmentVariableA("SteamAppId",(LPSTR)0x0,0);
      if (DVar4 == 0) {
        local_10[0] = '\0';
        __snprintf(local_10,0xc,"%u",uVar3);
        local_5 = 0;
        SetEnvironmentVariableA("SteamAppId",local_10);
      }
      DVar4 = GetEnvironmentVariableA("SteamAppId",(LPSTR)0x0,0);
      if (DVar4 == 0) {
        local_c = 0;
        __snprintf(&stack0xffffffd8,0x18,"%llu",(ulonglong)(uVar3 & 0xffffff));
        SetEnvironmentVariableA("SteamGameId",&stack0xffffffd8);
      }
      SteamAPI_SetBreakpadAppID(uVar3);
      FUN_3b402b60(DAT_3b41715c);
      FUN_3b403ca0();
      FUN_3b4031a0();
      if (param_1 == '\0') {
        if (DAT_3b417290 != (int *)0x0) {
          puVar5 = (undefined4 *)(**(code **)(*DAT_3b417290 + 8))(&local_c);
          uVar6 = FUN_3b403340(*puVar5,puVar5[1]);
          return CONCAT31((int3)((uint)uVar6 >> 8),1);
        }
        piVar2 = (int *)FUN_3b403340(0,0);
      }
      else {
        piVar2 = (int *)(**(code **)(*DAT_3b417158 + 0x14))
                                  (DAT_3b417160,DAT_3b417164,"SteamUser016");
        if (piVar2 != (int *)0x0) {
          puVar5 = (undefined4 *)(**(code **)(*piVar2 + 8))(&local_c);
          uVar6 = FUN_3b403340(*puVar5,puVar5[1]);
          return CONCAT31((int3)((uint)uVar6 >> 8),1);
        }
      }
      return CONCAT31((int3)((uint)piVar2 >> 8),1);
    }
  }
  else {
    piVar2 = (int *)(**(code **)(*DAT_3b417158 + 0x24))(DAT_3b417160,"SteamUtils005");
    if (piVar2 != (int *)0x0) {
      iVar7 = *piVar2;
      goto LAB_3b404078;
    }
  }
  OutputDebugStringA(
                    "[S_API FAIL] SteamAPI_Init() failed; no appID found.\nEither launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder.\n"
                    );
LAB_3b40408e:
  uVar3 = SteamAPI_Shutdown();
  return uVar3 & 0xffffff00;
}



void SteamAPI_InitSafe(void)

{
                    // 0x41e0  7  SteamAPI_InitSafe
  FUN_3b403fd0('\x01');
  return;
}



void SteamAPI_Init(void)

{
                    // 0x41f0  6  SteamAPI_Init
  FUN_3b403fd0('\0');
  return;
}



undefined4 SteamContentServer(void)

{
                    // 0x4200  23  SteamContentServer
  return DAT_3b4173c4;
}



undefined4 SteamContentServerUtils(void)

{
                    // 0x4210  24  SteamContentServerUtils
  return DAT_3b4173cc;
}



undefined4 __cdecl SteamContentServer_Init(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
                    // 0x4220  25  SteamContentServer_Init
  piVar1 = (int *)FUN_3b403b60(&DAT_3b4173d8,'\x01');
  DAT_3b4173c8 = piVar1;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0x1c))(param_2,param_3);
    piVar1 = (int *)(**(code **)(*DAT_3b4173c8 + 0xc))(&DAT_3b4173d0,6);
    DAT_3b4173d4 = piVar1;
    if ((piVar1 != (int *)0x0) && (DAT_3b4173d0 != 0)) {
      piVar1 = (int *)(**(code **)(*DAT_3b4173c8 + 0x30))
                                (piVar1,DAT_3b4173d0,"SteamContentServer002");
      DAT_3b4173c4 = piVar1;
      if (piVar1 != (int *)0x0) {
        piVar1 = (int *)(**(code **)(*DAT_3b4173c8 + 0x24))(DAT_3b4173d0,"SteamUtils005");
        DAT_3b4173cc = piVar1;
        if (piVar1 != (int *)0x0) {
          (**(code **)*DAT_3b4173c4)(param_1);
          uVar2 = Steam_RegisterInterfaceFuncs(DAT_3b4173d8);
          return CONCAT31((int3)((uint)uVar2 >> 8),1);
        }
      }
    }
  }
  return (uint)piVar1 & 0xffffff00;
}



void SteamContentServer_Shutdown(void)

{
  char cVar1;
  
                    // 0x42e0  27  SteamContentServer_Shutdown
  if (DAT_3b4173c4 != (int *)0x0) {
    cVar1 = (**(code **)(*DAT_3b4173c4 + 8))();
    if (cVar1 != '\0') {
      (**(code **)(*DAT_3b4173c4 + 4))();
    }
  }
  if (DAT_3b4173c8 != (int *)0x0) {
    if ((DAT_3b4173d0 != 0) && (DAT_3b4173d4 != 0)) {
      (**(code **)(*DAT_3b4173c8 + 0x10))(DAT_3b4173d0,DAT_3b4173d4);
    }
    DAT_3b4173c4 = (int *)0x0;
    if (DAT_3b4173d0 != 0) {
      (**(code **)(*DAT_3b4173c8 + 4))(DAT_3b4173d0);
    }
    DAT_3b4173d0 = 0;
    if (DAT_3b4173c8 != (int *)0x0) {
      (**(code **)(*DAT_3b4173c8 + 0x58))();
    }
    DAT_3b4173c8 = (int *)0x0;
    if (DAT_3b4173d8 != (HMODULE)0x0) {
      FUN_3b403c80(DAT_3b4173d8);
    }
    DAT_3b4173d8 = (HMODULE)0x0;
  }
  return;
}



void SteamContentServer_RunCallbacks(void)

{
                    // 0x4390  26  SteamContentServer_RunCallbacks
  if (DAT_3b4173d0 != 0) {
    Steam_RunCallbacks(DAT_3b4173d0,1);
  }
  return;
}



undefined4 SteamGameServer(void)

{
                    // 0x43b0  29  SteamGameServer
  return DAT_3b4173e0;
}



undefined4 SteamGameServerUtils(void)

{
                    // 0x43c0  34  SteamGameServerUtils
  return DAT_3b4173e8;
}



undefined4 SteamGameServerApps(void)

{
                    // 0x43d0  30  SteamGameServerApps
  return DAT_3b4173f4;
}



undefined4 SteamGameServerNetworking(void)

{
                    // 0x43e0  32  SteamGameServerNetworking
  return DAT_3b4173ec;
}



undefined4 SteamGameServerStats(void)

{
                    // 0x43f0  33  SteamGameServerStats
  return DAT_3b4173f0;
}



undefined4 SteamGameServerHTTP(void)

{
                    // 0x4400  31  SteamGameServerHTTP
  return DAT_3b4173f8;
}



undefined4 SteamGameServer_GetHSteamPipe(void)

{
                    // 0x4410  36  SteamGameServer_GetHSteamPipe
  return DAT_3b4173fc;
}



undefined4 SteamGameServer_GetHSteamUser(void)

{
                    // 0x4420  37  SteamGameServer_GetHSteamUser
  return DAT_3b417400;
}



uint __cdecl
FUN_3b404430(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,char param_7)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  byte bVar5;
  
  DAT_3b4173dc = param_5;
  piVar1 = (int *)FUN_3b403b60(&DAT_3b417404,'\x01');
  g_pSteamClientGameServer = piVar1;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0x1c))(param_1,param_2);
    piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0xc))(&DAT_3b4173fc,3);
    DAT_3b417400 = piVar1;
    if ((piVar1 != (int *)0x0) && (DAT_3b4173fc != 0)) {
      piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0x18))
                                (piVar1,DAT_3b4173fc,"SteamGameServer011");
      DAT_3b4173e0 = piVar1;
      if (piVar1 != (int *)0x0) {
        piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0x24))
                                  (DAT_3b4173fc,"SteamUtils005");
        DAT_3b4173e8 = piVar1;
        if (piVar1 != (int *)0x0) {
          piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0x3c))
                                    (DAT_3b417400,DAT_3b4173fc,"STEAMAPPS_INTERFACE_VERSION005");
          DAT_3b4173f4 = piVar1;
          if (piVar1 != (int *)0x0) {
            piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0x5c))
                                      (DAT_3b417400,DAT_3b4173fc,"STEAMHTTP_INTERFACE_VERSION002");
            DAT_3b4173f8 = piVar1;
            if (piVar1 != (int *)0x0) {
              if (param_7 != '\0') {
LAB_3b404581:
                bVar5 = (DAT_3b4173dc != 3) - 1U & 2;
                if (DAT_3b4173dc == 1) {
                  bVar5 = bVar5 | 0x20;
                }
                uVar2 = (**(code **)(*DAT_3b4173e8 + 0x24))();
                uVar3 = uVar2;
                if (uVar2 != 0) {
                  uVar3 = (**(code **)*DAT_3b4173e0)(param_1,param_3,param_4,bVar5,uVar2,param_6);
                  if ((char)uVar3 != '\0') {
                    if (param_7 != '\0') {
                      DAT_3b4173e0 = (int *)0x0;
                      DAT_3b4173e8 = (int *)0x0;
                    }
                    Steam_RegisterInterfaceFuncs(DAT_3b417404);
                    SteamAPI_SetBreakpadAppID(uVar2);
                    uVar4 = FUN_3b403ca0();
                    return CONCAT31((int3)((uint)uVar4 >> 8),1);
                  }
                }
                return uVar3 & 0xffffff00;
              }
              piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0x40))
                                        (DAT_3b417400,DAT_3b4173fc,"SteamNetworking005");
              DAT_3b4173ec = piVar1;
              if (piVar1 != (int *)0x0) {
                piVar1 = (int *)(**(code **)(*g_pSteamClientGameServer + 0x38))
                                          (DAT_3b417400,DAT_3b4173fc,"SteamGameServerStats001");
                DAT_3b4173f0 = piVar1;
                if (piVar1 != (int *)0x0) goto LAB_3b404581;
              }
            }
          }
        }
      }
      return (uint)piVar1 & 0xffffff00;
    }
  }
  return (uint)piVar1 & 0xffffff00;
}



void __cdecl
SteamGameServer_InitSafe
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,
          undefined4 param_6)

{
                    // 0x4620  41  SteamGameServer_InitSafe
  FUN_3b404430(param_1,param_2,param_3,param_4,param_5,param_6,'\x01');
  return;
}



void __cdecl
SteamGameServer_Init
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,
          undefined4 param_6)

{
                    // 0x4650  40  SteamGameServer_Init
  FUN_3b404430(param_1,param_2,param_3,param_4,param_5,param_6,'\0');
  return;
}



void SteamGameServer_Shutdown(void)

{
  char cVar1;
  
                    // 0x4680  43  SteamGameServer_Shutdown
  if (DAT_3b4173e0 != (int *)0x0) {
    cVar1 = (**(code **)(*DAT_3b4173e0 + 0x20))();
    if (cVar1 != '\0') {
      (**(code **)(*DAT_3b4173e0 + 0x1c))();
    }
  }
  if (g_pSteamClientGameServer != (int *)0x0) {
    if ((DAT_3b4173fc != 0) && (DAT_3b417400 != 0)) {
      (**(code **)(*g_pSteamClientGameServer + 0x10))(DAT_3b4173fc,DAT_3b417400);
    }
    DAT_3b4173e0 = (int *)0x0;
    if (DAT_3b4173fc != 0) {
      (**(code **)(*g_pSteamClientGameServer + 4))(DAT_3b4173fc);
    }
    DAT_3b4173fc = 0;
    if (g_pSteamClientGameServer != (int *)0x0) {
      (**(code **)(*g_pSteamClientGameServer + 0x58))();
    }
    g_pSteamClientGameServer = (int *)0x0;
    if (DAT_3b417404 != (HMODULE)0x0) {
      FUN_3b403c80(DAT_3b417404);
    }
    DAT_3b417404 = (HMODULE)0x0;
  }
  return;
}



void SteamGameServer_RunCallbacks(void)

{
                    // 0x4730  42  SteamGameServer_RunCallbacks
  if (DAT_3b4173fc != 0) {
    Steam_RunCallbacks(DAT_3b4173fc,1);
  }
  return;
}



uint SteamGameServer_BSecure(void)

{
  uint in_EAX;
  uint uVar1;
  
                    // 0x4750  35  SteamGameServer_BSecure
  if ((DAT_3b4173dc != 1) && (DAT_3b4173e0 != (int *)0x0)) {
                    // WARNING: Could not recover jumptable at 0x3b40476b. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (**(code **)(*DAT_3b4173e0 + 0x24))();
    return uVar1;
  }
  return in_EAX & 0xffffff00;
}



undefined4 SteamGameServer_GetIPCCallCount(void)

{
  undefined4 uVar1;
  
                    // 0x4770  38  SteamGameServer_GetIPCCallCount
  if (DAT_3b4173e8 != (int *)0x0) {
                    // WARNING: Could not recover jumptable at 0x3b40477f. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (**(code **)(*DAT_3b4173e8 + 0x3c))();
    return uVar1;
  }
  return 0;
}



undefined8 SteamGameServer_GetSteamID(void)

{
  undefined8 *puVar1;
  undefined local_c [8];
  
                    // 0x4790  39  SteamGameServer_GetSteamID
  if (DAT_3b4173dc == 1) {
    return 0x100000000000000;
  }
  if (DAT_3b4173e0 == (int *)0x0) {
    return 1;
  }
  puVar1 = (undefined8 *)(**(code **)(*DAT_3b4173e0 + 0x28))(local_c);
  return *puVar1;
}



undefined4 * __thiscall FUN_3b4047d9(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_3b4119cc;
  return (undefined4 *)this;
}



void FUN_3b4047f6(char *param_1)

{
  code *pcVar1;
  undefined **local_10 [3];
  
  std::exception::exception((exception *)local_10,&param_1);
  local_10[0] = &PTR_FUN_3b4119d8;
  __CxxThrowException_8(local_10,&DAT_3b413f68);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined4 * __thiscall FUN_3b404826(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_3b4119d8;
  return (undefined4 *)this;
}



void FUN_3b404843(char *param_1)

{
  code *pcVar1;
  undefined **local_10 [3];
  
  std::exception::exception((exception *)local_10,&param_1);
  local_10[0] = &PTR_FUN_3b4119e4;
  __CxxThrowException_8(local_10,&DAT_3b413fa4);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined4 * __thiscall FUN_3b404873(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_3b4119e4;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_3b404890(void *this,byte param_1)

{
  FUN_3b404995((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_3b404a3d(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &,int)
// 
// Library: Visual Studio 2010 Release

void __thiscall std::exception::exception(exception *this,char **param_1,int param_2)

{
  *(undefined ***)this = &PTR_FUN_3b4119f0;
  *(char **)(this + 4) = *param_1;
  this[8] = (exception)0x0;
  return;
}



// Library Function - Single Match
//  private: void __thiscall std::exception::_Copy_str(char const *)
// 
// Library: Visual Studio 2010 Release

void __thiscall std::exception::_Copy_str(exception *this,char *param_1)

{
  size_t sVar1;
  char *_Dst;
  
  if (param_1 != (char *)0x0) {
    sVar1 = _strlen(param_1);
    _Dst = (char *)_malloc(sVar1 + 1);
    *(char **)(this + 4) = _Dst;
    if (_Dst != (char *)0x0) {
      _strcpy_s(_Dst,sVar1 + 1,param_1);
      this[8] = (exception)0x1;
    }
  }
  return;
}



// Library Function - Single Match
//  private: void __thiscall std::exception::_Tidy(void)
// 
// Library: Visual Studio 2010 Release

void __thiscall std::exception::_Tidy(exception *this)

{
  if (this[8] != (exception)0x0) {
    _free(*(void **)(this + 4));
  }
  *(undefined4 *)(this + 4) = 0;
  this[8] = (exception)0x0;
  return;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2010 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_3b4119f0;
  this[8] = (exception)0x0;
  _Copy_str(this,*param_1);
  return this;
}



// Library Function - Single Match
//  public: class std::exception & __thiscall std::exception::operator=(class std::exception const
// &)
// 
// Library: Visual Studio 2010 Release

exception * __thiscall std::exception::operator=(exception *this,exception *param_1)

{
  if (this != param_1) {
    _Tidy(this);
    if (param_1[8] == (exception)0x0) {
      *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
    }
    else {
      _Copy_str(this,*(char **)(param_1 + 4));
    }
  }
  return this;
}



void __fastcall FUN_3b404995(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_3b4119f0;
  std::exception::_Tidy((exception *)param_1);
  return;
}



undefined4 * __thiscall FUN_3b4049a0(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_3b4119f0;
  std::exception::_Tidy((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_3b404a3d(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2010 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_3b4119f0;
  this[8] = (exception)0x0;
  operator=(this,param_1);
  return this;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall type_info::~type_info(type_info *this)

{
  *(undefined ***)this = &PTR__scalar_deleting_destructor__3b411a10;
  _Type_info_dtor(this);
  return;
}



// Library Function - Single Match
//  public: virtual void * __thiscall type_info::`scalar deleting destructor'(unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void * __thiscall type_info::_scalar_deleting_destructor_(type_info *this,uint param_1)

{
  ~type_info(this);
  if ((param_1 & 1) != 0) {
    FUN_3b404a3d(this);
  }
  return this;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Library: Visual Studio 2010 Release

bool __thiscall type_info::operator==(type_info *this,type_info *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp((char *)(param_1 + 9),(char *)(this + 9));
  return (bool)('\x01' - (iVar1 != 0));
}



void FUN_3b404a3d(void *param_1)

{
  _free(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2010 Release

void * __cdecl operator_new(uint param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  undefined **local_14 [3];
  char *local_8;
  
  do {
    pvVar3 = _malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = __callnewh(param_1);
  } while (iVar2 != 0);
  if ((_DAT_3b417414 & 1) == 0) {
    _DAT_3b417414 = _DAT_3b417414 | 1;
    local_8 = "bad allocation";
    std::exception::exception((exception *)&DAT_3b417408,&local_8,1);
    _DAT_3b417408 = &PTR_FUN_3b4111a0;
    _atexit((_func_4879 *)&LAB_3b410cba);
  }
  std::exception::exception((exception *)local_14,(exception *)&DAT_3b417408);
  local_14[0] = &PTR_FUN_3b4111a0;
  __CxxThrowException_8(local_14,&DAT_3b413dc0);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



// Library Function - Single Match
//  __CxxThrowException@8
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __CxxThrowException_8(undefined4 param_1,byte *param_2)

{
  int iVar1;
  DWORD *pDVar2;
  DWORD *pDVar3;
  DWORD local_24 [4];
  DWORD local_14;
  ULONG_PTR local_10;
  undefined4 local_c;
  byte *local_8;
  
  pDVar2 = &DAT_3b411a24;
  pDVar3 = local_24;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pDVar3 = *pDVar2;
    pDVar2 = pDVar2 + 1;
    pDVar3 = pDVar3 + 1;
  }
  local_c = param_1;
  local_8 = param_2;
  if ((param_2 != (byte *)0x0) && ((*param_2 & 8) != 0)) {
    local_10 = 0x1994000;
  }
  RaiseException(local_24[0],local_24[1],local_14,&local_10);
  return;
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
  undefined4 *unaff_FS_OFFSET;
  
  *unaff_FS_OFFSET = *(undefined4 *)*unaff_FS_OFFSET;
                    // WARNING: Could not recover jumptable at 0x3b404b3f. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_1)();
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  void __stdcall _CallMemberFunction1(void *,void *,void *)
//  void __stdcall _CallMemberFunction2(void *,void *,void *,int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void FID_conflict__CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x3b404b4b. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Library: Visual Studio 2010 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  
  puVar1 = (undefined4 *)*unaff_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x3b404b78,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *puVar1 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = puVar1;
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___CxxFrameHandler
//  ___CxxFrameHandler2
//  ___CxxFrameHandler3
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl
FID_conflict____CxxFrameHandler3
          (int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4)

{
  uint *in_EAX;
  undefined4 uVar1;
  
  uVar1 = ___InternalCxxFrameHandler
                    (param_1,param_2,param_3,param_4,in_EAX,0,(EHRegistrationNode *)0x0,'\0');
  return uVar1;
}



// Library Function - Single Match
//  enum _EXCEPTION_DISPOSITION __cdecl CatchGuardHandler(struct EHExceptionRecord *,struct
// CatchGuardRN *,void *,void *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

_EXCEPTION_DISPOSITION __cdecl
CatchGuardHandler(EHExceptionRecord *param_1,CatchGuardRN *param_2,void *param_3,void *param_4)

{
  _EXCEPTION_DISPOSITION _Var1;
  
  ___security_check_cookie_4(*(uint *)(param_2 + 8) ^ (uint)param_2);
  _Var1 = ___InternalCxxFrameHandler
                    ((int *)param_1,*(EHRegistrationNode **)(param_2 + 0x10),(_CONTEXT *)param_3,
                     (void *)0x0,*(uint **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
                     (EHRegistrationNode *)param_2,'\0');
  return _Var1;
}



// Library Function - Single Match
//  int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void
// *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2010 Release

int __cdecl
_CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4
                 ,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7)

{
  _ptiddata p_Var1;
  int *unaff_FS_OFFSET;
  int local_3c;
  EHExceptionRecord *local_38;
  void *local_34;
  code *local_30;
  undefined4 *local_2c;
  code *local_28;
  uint local_24;
  _s_FuncInfo *local_20;
  EHRegistrationNode *local_1c;
  int local_18;
  EHRegistrationNode *local_14;
  undefined *local_10;
  undefined *local_c;
  int local_8;
  
  local_c = &stack0xfffffffc;
  local_10 = &stack0xffffffc0;
  if (param_1 == (EHExceptionRecord *)0x123) {
    *(undefined4 *)param_2 = 0x3b404cb5;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = securityCookie ^ (uint)&local_2c;
    local_20 = param_5;
    local_1c = param_2;
    local_18 = param_6;
    local_14 = param_7;
    local_8 = 0;
    local_2c = (undefined4 *)*unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (int)&local_2c;
    local_38 = param_1;
    local_34 = param_3;
    p_Var1 = __getptd();
    local_30 = (code *)p_Var1->_translator;
    (*local_30)(*(undefined4 *)param_1,&local_38);
    local_3c = 0;
    if (local_8 == 0) {
      *unaff_FS_OFFSET = (int)local_2c;
    }
    else {
      *local_2c = *(undefined4 *)*unaff_FS_OFFSET;
      *unaff_FS_OFFSET = (int)local_2c;
    }
  }
  return local_3c;
}



// Library Function - Single Match
//  enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct
// TranslatorGuardRN *,void *,void *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

_EXCEPTION_DISPOSITION __cdecl
TranslatorGuardHandler
          (EHExceptionRecord *param_1,TranslatorGuardRN *param_2,void *param_3,void *param_4)

{
  _EXCEPTION_DISPOSITION _Var1;
  code *local_8;
  
  ___security_check_cookie_4(*(uint *)(param_2 + 8) ^ (uint)param_2);
  if ((*(uint *)(param_1 + 4) & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  ___InternalCxxFrameHandler
            ((int *)param_1,*(EHRegistrationNode **)(param_2 + 0x10),(_CONTEXT *)param_3,(void *)0x0
             ,*(uint **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
             *(EHRegistrationNode **)(param_2 + 0x18),'\x01');
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames((EHRegistrationNode *)param_2,param_1);
  }
  _CallSETranslator((EHExceptionRecord *)0x123,(EHRegistrationNode *)&local_8,(void *)0x0,
                    (void *)0x0,(_s_FuncInfo *)0x0,0,(EHRegistrationNode *)0x0);
                    // WARNING: Could not recover jumptable at 0x3b404d78. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = (*local_8)();
  return _Var1;
}



// Library Function - Single Match
//  struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const
// *,int,int,unsigned int *,unsigned int *)
// 
// Library: Visual Studio 2010 Release

_s_TryBlockMapEntry * __cdecl
_GetRangeOfTrysToCheck(_s_FuncInfo *param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  iVar1 = *(int *)(param_1 + 0x10);
  uVar6 = *(uint *)(param_1 + 0xc);
  uVar2 = uVar6;
  uVar4 = uVar6;
  while (uVar5 = uVar2, -1 < param_2) {
    if (uVar6 == 0xffffffff) {
      _inconsistency();
    }
    uVar6 = uVar6 - 1;
    iVar3 = uVar6 * 0x14 + iVar1;
    if (((*(int *)(iVar3 + 4) < param_3) && (param_3 <= *(int *)(iVar3 + 8))) ||
       (uVar2 = uVar5, uVar6 == 0xffffffff)) {
      param_2 = param_2 + -1;
      uVar2 = uVar6;
      uVar4 = uVar5;
    }
  }
  uVar6 = uVar6 + 1;
  *param_4 = uVar6;
  *param_5 = uVar4;
  if ((*(uint *)(param_1 + 0xc) < uVar4) || (uVar4 < uVar6)) {
    _inconsistency();
  }
  return (_s_TryBlockMapEntry *)(uVar6 * 0x14 + iVar1);
}



// Library Function - Single Match
//  __CreateFrameInfo
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 * __cdecl __CreateFrameInfo(undefined4 *param_1,undefined4 param_2)

{
  _ptiddata p_Var1;
  
  *param_1 = param_2;
  p_Var1 = __getptd();
  param_1[1] = p_Var1->_pFrameInfoChain;
  p_Var1 = __getptd();
  p_Var1->_pFrameInfoChain = param_1;
  return param_1;
}



// Library Function - Single Match
//  __IsExceptionObjectToBeDestroyed
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl __IsExceptionObjectToBeDestroyed(int param_1)

{
  _ptiddata p_Var1;
  int *piVar2;
  
  p_Var1 = __getptd();
  piVar2 = (int *)p_Var1->_pFrameInfoChain;
  while( true ) {
    if (piVar2 == (int *)0x0) {
      return 1;
    }
    if (*piVar2 == param_1) break;
    piVar2 = (int *)piVar2[1];
  }
  return 0;
}



// Library Function - Single Match
//  __FindAndUnlinkFrame
// 
// Library: Visual Studio 2010 Release

void __cdecl __FindAndUnlinkFrame(void *param_1)

{
  void *pvVar1;
  _ptiddata p_Var2;
  void *pvVar3;
  
  p_Var2 = __getptd();
  if (param_1 == p_Var2->_pFrameInfoChain) {
    p_Var2 = __getptd();
    p_Var2->_pFrameInfoChain = *(void **)((int)param_1 + 4);
  }
  else {
    p_Var2 = __getptd();
    pvVar1 = p_Var2->_pFrameInfoChain;
    do {
      pvVar3 = pvVar1;
      if (*(int *)((int)pvVar3 + 4) == 0) {
        _inconsistency();
        return;
      }
      pvVar1 = *(void **)((int)pvVar3 + 4);
    } while (param_1 != *(void **)((int)pvVar3 + 4));
    *(undefined4 *)((int)pvVar3 + 4) = *(undefined4 *)((int)param_1 + 4);
  }
  return;
}



// Library Function - Single Match
//  void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *,struct _s_FuncInfo const *,void
// *,int,unsigned long)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl
_CallCatchBlock2(EHRegistrationNode *param_1,_s_FuncInfo *param_2,void *param_3,int param_4,
                ulong param_5)

{
  void *pvVar1;
  int **unaff_FS_OFFSET;
  int *local_1c;
  code *local_18;
  uint local_14;
  _s_FuncInfo *local_10;
  EHRegistrationNode *local_c;
  int local_8;
  
  local_14 = securityCookie ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = CatchGuardHandler;
  local_c = param_1;
  local_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_1c;
  pvVar1 = (void *)__CallSettingFrame_12(param_3,param_1,param_5);
  *unaff_FS_OFFSET = local_1c;
  return pvVar1;
}



// Library Function - Single Match
//  _free
// 
// Library: Visual Studio 2010 Release

void __cdecl _free(void *_Memory)

{
  BOOL BVar1;
  int *piVar2;
  DWORD DVar3;
  int iVar4;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(hHeap_3b417a7c,0,_Memory);
    if (BVar1 == 0) {
      piVar2 = __errno();
      DVar3 = GetLastError();
      iVar4 = __get_errno_from_oserr(DVar3);
      *piVar2 = iVar4;
    }
  }
  return;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl _malloc(size_t _Size)

{
  SIZE_T dwBytes;
  LPVOID pvVar1;
  int iVar2;
  int *piVar3;
  
  if (_Size < 0xffffffe1) {
    do {
      if (hHeap_3b417a7c == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
      pvVar1 = HeapAlloc(hHeap_3b417a7c,0,dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_3b417ab4 == 0) {
        piVar3 = __errno();
        *piVar3 = 0xc;
        break;
      }
      iVar2 = __callnewh(_Size);
    } while (iVar2 != 0);
    piVar3 = __errno();
    *piVar3 = 0xc;
  }
  else {
    __callnewh(_Size);
    piVar3 = __errno();
    *piVar3 = 0xc;
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl __onexit_nolock(undefined4 param_1)

{
  undefined *puVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  size_t sVar3;
  size_t sVar4;
  void *pvVar5;
  undefined4 uVar6;
  int iVar7;
  
  puVar1 = PTR_FUN_3b416004;
  _Memory = (undefined4 *)(*(code *)PTR_FUN_3b416004)(DAT_3b418208);
  puVar2 = (undefined4 *)(*(code *)puVar1)(DAT_3b418204);
  if ((puVar2 < _Memory) || (iVar7 = (int)puVar2 - (int)_Memory, iVar7 + 4U < 4)) {
    return 0;
  }
  sVar3 = __msize(_Memory);
  if (sVar3 < iVar7 + 4U) {
    sVar4 = 0x800;
    if (sVar3 < 0x800) {
      sVar4 = sVar3;
    }
    if ((sVar4 + sVar3 < sVar3) ||
       (pvVar5 = __realloc_crt(_Memory,sVar4 + sVar3), pvVar5 == (void *)0x0)) {
      if (sVar3 + 0x10 < sVar3) {
        return 0;
      }
      pvVar5 = __realloc_crt(_Memory,sVar3 + 0x10);
      if (pvVar5 == (void *)0x0) {
        return 0;
      }
    }
    puVar2 = (undefined4 *)((int)pvVar5 + (iVar7 >> 2) * 4);
    DAT_3b418208 = (*(code *)PTR_FUN_3b416000)(pvVar5);
  }
  puVar1 = PTR_FUN_3b416000;
  uVar6 = (*(code *)PTR_FUN_3b416000)(param_1);
  *puVar2 = uVar6;
  DAT_3b418204 = (*(code *)puVar1)(puVar2 + 1);
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2010 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
  FUN_3b40788c();
  p_Var1 = (_onexit_t)__onexit_nolock(_Func);
  FUN_3b4050e3();
  return p_Var1;
}



void FUN_3b4050e3(void)

{
  FUN_3b407895();
  return;
}



// Library Function - Single Match
//  _atexit
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    iVar3 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar3 = __flush(_File);
      __freebuf(_File);
      iVar2 = __fileno(_File);
      iVar2 = __close(iVar2);
      if (iVar2 < 0) {
        iVar3 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        _free(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    _File->_flag = 0;
  }
  return iVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fclose
// 
// Library: Visual Studio 2010 Release

int __cdecl _fclose(FILE *_File)

{
  int *piVar1;
  int local_20;
  
  local_20 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    local_20 = -1;
  }
  else if ((*(byte *)&_File->_flag & 0x40) == 0) {
    __lock_file(_File);
    local_20 = __fclose_nolock(_File);
    FUN_3b4051d9();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_3b4051d9(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



void __cdecl FUN_3b4051e1(char *param_1)

{
  _strtol(param_1,(char **)0x0,10);
  return;
}



void __cdecl FUN_3b4051f7(char *param_1)

{
  FUN_3b4051e1(param_1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fgets
// 
// Library: Visual Studio 2010 Release

char * __cdecl _fgets(char *_Buf,int _MaxCount,FILE *_File)

{
  int *piVar1;
  uint uVar2;
  undefined *puVar3;
  char *pcVar4;
  char *local_20;
  
  local_20 = _Buf;
  if ((((_Buf == (char *)0x0) && (_MaxCount != 0)) || (_MaxCount < 0)) || (_File == (FILE *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
  }
  else if (_MaxCount != 0) {
    __lock_file(_File);
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar2 = __fileno(_File);
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar3 = &DAT_3b4165d0;
      }
      else {
        puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar2 >> 5]);
      }
      if ((puVar3[0x24] & 0x7f) == 0) {
        if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
          puVar3 = &DAT_3b4165d0;
        }
        else {
          puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar2 >> 5]);
        }
        if ((puVar3[0x24] & 0x80) == 0) goto LAB_3b4052da;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_3b408343();
      local_20 = (char *)0x0;
    }
LAB_3b4052da:
    pcVar4 = _Buf;
    if (local_20 != (char *)0x0) {
      do {
        _MaxCount = _MaxCount + -1;
        if (_MaxCount == 0) break;
        piVar1 = &_File->_cnt;
        *piVar1 = *piVar1 + -1;
        if (*piVar1 < 0) {
          uVar2 = __filbuf(_File);
        }
        else {
          uVar2 = (uint)(byte)*_File->_ptr;
          _File->_ptr = _File->_ptr + 1;
        }
        if (uVar2 == 0xffffffff) {
          if (pcVar4 == _Buf) {
            local_20 = (char *)0x0;
            goto LAB_3b40531a;
          }
          break;
        }
        *pcVar4 = (char)uVar2;
        pcVar4 = pcVar4 + 1;
      } while ((char)uVar2 != '\n');
      *pcVar4 = '\0';
    }
LAB_3b40531a:
    FUN_3b405332();
    return local_20;
  }
  return (char *)0x0;
}



void FUN_3b405332(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __fsopen
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_3b414040;
  uStack_c = 0x3b405346;
  if (((_Filename == (char *)0x0) || (_Mode == (char *)0x0)) || (*_Mode == '\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
  }
  else {
    pFVar2 = __getstream();
    if (pFVar2 == (FILE *)0x0) {
      piVar1 = __errno();
      *piVar1 = 0x18;
    }
    else {
      local_8 = (undefined *)0x0;
      if (*_Filename != '\0') {
        pFVar2 = __openfile(_Filename,_Mode,_ShFlag,pFVar2);
        local_8 = (undefined *)0xfffffffe;
        FUN_3b4053ec();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&securityCookie,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_3b4053ec(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  _fopen
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl _fopen(char *_Filename,char *_Mode)

{
  FILE *pFVar1;
  
  pFVar1 = __fsopen(_Filename,_Mode,0x40);
  return pFVar1;
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  size_t sVar4;
  uint *puVar5;
  
  if (_Size == 0) {
    return _Dst;
  }
  uVar1 = _Val & 0xff;
  if ((((char)_Val == '\0') && (0x7f < _Size)) && (DAT_3b4180e8 != 0)) {
    pauVar2 = __VEC_memzero((undefined (*) [16])_Dst,_Size);
    return pauVar2;
  }
  puVar5 = (uint *)_Dst;
  if (3 < _Size) {
    uVar3 = -(int)_Dst & 3;
    sVar4 = _Size;
    if (uVar3 != 0) {
      sVar4 = _Size - uVar3;
      do {
        *(char *)puVar5 = (char)_Val;
        puVar5 = (uint *)((int)puVar5 + 1);
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    _Size = sVar4 & 3;
    uVar3 = sVar4 >> 2;
    if (uVar3 != 0) {
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar5 = uVar1;
        puVar5 = puVar5 + 1;
      }
      if (_Size == 0) {
        return _Dst;
      }
    }
  }
  do {
    *(char *)puVar5 = (char)uVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    _Size = _Size - 1;
  } while (_Size != 0);
  return _Dst;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct *)
// 
// Library: Visual Studio 2010 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1)

{
  uint *puVar1;
  _ptiddata p_Var2;
  pthreadlocinfo ptVar3;
  pthreadmbcinfo ptVar4;
  
  this[0xc] = (_LocaleUpdate)0x0;
  if (param_1 == (localeinfo_struct *)0x0) {
    p_Var2 = __getptd();
    *(_ptiddata *)(this + 8) = p_Var2;
    *(pthreadlocinfo *)this = p_Var2->ptlocinfo;
    *(pthreadmbcinfo *)(this + 4) = p_Var2->ptmbcinfo;
    if ((*(undefined **)this != PTR_DAT_3b416d78) && ((p_Var2->_ownlocale & DAT_3b416b30) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != lpAddend_3b416a38) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_3b416b30) == 0)) {
      ptVar4 = ___updatetmbcinfo();
      *(pthreadmbcinfo *)(this + 4) = ptVar4;
    }
    if ((*(byte *)(*(int *)(this + 8) + 0x70) & 2) == 0) {
      puVar1 = (uint *)(*(int *)(this + 8) + 0x70);
      *puVar1 = *puVar1 | 2;
      this[0xc] = (_LocaleUpdate)0x1;
    }
  }
  else {
    *(pthreadlocinfo *)this = param_1->locinfo;
    *(pthreadmbcinfo *)(this + 4) = param_1->mbcinfo;
  }
  return this;
}



// Library Function - Single Match
//  ___ascii_stricmp
// 
// Library: Visual Studio 2010 Release

int __cdecl ___ascii_stricmp(char *_Str1,char *_Str2)

{
  uint uVar1;
  uint uVar2;
  
  do {
    uVar1 = (uint)(byte)*_Str1;
    _Str1 = (char *)((byte *)_Str1 + 1);
    if (uVar1 - 0x41 < 0x1a) {
      uVar1 = uVar1 + 0x20;
    }
    uVar2 = (uint)(byte)*_Str2;
    _Str2 = (char *)((byte *)_Str2 + 1);
    if (uVar2 - 0x41 < 0x1a) {
      uVar2 = uVar2 + 0x20;
    }
  } while ((uVar1 != 0) && (uVar1 == uVar2));
  return uVar1 - uVar2;
}



// Library Function - Single Match
//  __stricmp_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __stricmp_l(char *_Str1,char *_Str2,_locale_t _Locale)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if (_Str1 == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  else if (_Str2 == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  else {
    if ((local_14.locinfo)->lc_category[0].wlocale == (wchar_t *)0x0) {
      iVar2 = ___ascii_stricmp(_Str1,_Str2);
    }
    else {
      iVar4 = (int)_Str1 - (int)_Str2;
      do {
        iVar2 = __tolower_l((uint)((byte *)_Str2)[iVar4],&local_14);
        iVar3 = __tolower_l((uint)(byte)*_Str2,&local_14);
        _Str2 = (char *)((byte *)_Str2 + 1);
        if (iVar2 == 0) break;
      } while (iVar2 == iVar3);
      iVar2 = iVar2 - iVar3;
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return iVar2;
}



// Library Function - Single Match
//  __stricmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __stricmp(char *_Str1,char *_Str2)

{
  int *piVar1;
  int iVar2;
  
  if (DAT_3b417adc != 0) {
    iVar2 = __stricmp_l(_Str1,_Str2,(_locale_t)0x0);
    return iVar2;
  }
  if ((_Str1 != (char *)0x0) && (_Str2 != (char *)0x0)) {
    iVar2 = ___ascii_stricmp(_Str1,_Str2);
    return iVar2;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  FUN_3b408343();
  return 0x7fffffff;
}



// Library Function - Single Match
//  _strncpy
// 
// Library: Visual Studio

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
        goto joined_r0x3b4056ac;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_3b4056f3;
        goto LAB_3b405769;
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
joined_r0x3b405765:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_3b405769:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_3b4056f3;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x3b405765;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x3b405765;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x3b405765;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x3b4056ac:
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
LAB_3b4056f3:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



// Library Function - Single Match
//  __snprintf
// 
// Library: Visual Studio 2010 Release

int __cdecl __snprintf(char *_Dest,size_t _Count,char *_Format,...)

{
  int *piVar1;
  int iVar2;
  char **ppcVar3;
  FILE local_24;
  
  local_24._ptr = (char *)0x0;
  ppcVar3 = (char **)&local_24._cnt;
  for (iVar2 = 7; iVar2 != 0; iVar2 = iVar2 + -1) {
    *ppcVar3 = (char *)0x0;
    ppcVar3 = ppcVar3 + 1;
  }
  if (_Format == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    iVar2 = -1;
  }
  else if ((_Count == 0) || (_Dest != (char *)0x0)) {
    local_24._cnt = 0x7fffffff;
    if (_Count < 0x80000000) {
      local_24._cnt = _Count;
    }
    local_24._flag = 0x42;
    local_24._base = _Dest;
    local_24._ptr = _Dest;
    iVar2 = FUN_3b409c77(&local_24,(byte *)_Format,(localeinfo_struct *)0x0,(int **)&stack0x00000010
                        );
    if (_Dest != (char *)0x0) {
      local_24._cnt = local_24._cnt - 1;
      if (local_24._cnt < 0) {
        __flsbuf(0,&local_24);
      }
      else {
        *local_24._ptr = '\0';
      }
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    iVar2 = -1;
  }
  return iVar2;
}



// Library Function - Single Match
//  _strncat
// 
// Library: Visual Studio

char * __cdecl _strncat(char *_Dest,char *_Source,size_t _Count)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  
  if (_Count != 0) {
    uVar4 = (uint)_Dest & 3;
    puVar5 = (uint *)_Dest;
    while (uVar4 != 0) {
      bVar1 = *(byte *)puVar5;
      puVar5 = (uint *)((int)puVar5 + 1);
      if (bVar1 == 0) goto LAB_3b40588d;
      uVar4 = (uint)puVar5 & 3;
    }
    do {
      do {
        puVar6 = puVar5;
        puVar5 = puVar6 + 1;
      } while (((*puVar6 ^ 0xffffffff ^ *puVar6 + 0x7efefeff) & 0x81010100) == 0);
      uVar4 = *puVar6;
      if ((char)uVar4 == '\0') goto LAB_3b40589f;
      if ((char)(uVar4 >> 8) == '\0') {
        puVar6 = (uint *)((int)puVar6 + 1);
        goto LAB_3b40589f;
      }
      if ((uVar4 & 0xff0000) == 0) {
        puVar6 = (uint *)((int)puVar6 + 2);
        goto LAB_3b40589f;
      }
    } while ((uVar4 & 0xff000000) != 0);
LAB_3b40588d:
    puVar6 = (uint *)((int)puVar5 + -1);
LAB_3b40589f:
    if (((uint)_Source & 3) == 0) {
      uVar3 = _Count >> 2;
    }
    else {
      do {
        bVar1 = *_Source;
        uVar4 = (uint)bVar1;
        _Source = (char *)((int)_Source + 1);
        if (bVar1 == 0) goto LAB_3b4058fa;
        *(byte *)puVar6 = bVar1;
        puVar6 = (uint *)((int)puVar6 + 1);
        _Count = _Count - 1;
        if (_Count == 0) goto LAB_3b4058f0;
      } while (((uint)_Source & 3) != 0);
      uVar3 = _Count >> 2;
    }
    for (; uVar3 != 0; uVar3 = uVar3 - 1) {
      uVar2 = *(uint *)_Source;
      uVar4 = *(uint *)_Source;
      _Source = (char *)((int)_Source + 4);
      if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar4 == '\0') {
LAB_3b4058fa:
          *(byte *)puVar6 = (byte)uVar4;
          return _Dest;
        }
        if ((char)(uVar4 >> 8) == '\0') {
          *(short *)puVar6 = (short)uVar4;
          return _Dest;
        }
        if ((uVar4 & 0xff0000) == 0) {
          *(short *)puVar6 = (short)uVar4;
          *(byte *)((int)puVar6 + 2) = 0;
          return _Dest;
        }
        if ((uVar4 & 0xff000000) == 0) {
          *puVar6 = uVar4;
          return _Dest;
        }
      }
      *puVar6 = uVar4;
      puVar6 = puVar6 + 1;
    }
    for (_Count = _Count & 3; _Count != 0; _Count = _Count - 1) {
      bVar1 = *_Source;
      _Source = (char *)((int)_Source + 1);
      *(byte *)puVar6 = bVar1;
      puVar6 = (uint *)((int)puVar6 + 1);
      if (bVar1 == 0) {
        return _Dest;
      }
    }
LAB_3b4058f0:
    *(byte *)puVar6 = (byte)_Count;
  }
  return _Dest;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fprintf
// 
// Library: Visual Studio 2010 Release

int __cdecl _fprintf(FILE *_File,char *_Format,...)

{
  int *piVar1;
  uint uVar2;
  int _Flag;
  undefined *puVar3;
  int local_20;
  
  local_20 = 0;
  if ((_File == (FILE *)0x0) || (_Format == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    return -1;
  }
  __lock_file(_File);
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    uVar2 = __fileno(_File);
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar3 = &DAT_3b4165d0;
    }
    else {
      puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar2 >> 5]);
    }
    if ((puVar3[0x24] & 0x7f) == 0) {
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar3 = &DAT_3b4165d0;
      }
      else {
        puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar2 >> 5]);
      }
      if ((puVar3[0x24] & 0x80) == 0) goto LAB_3b405a2a;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    local_20 = -1;
  }
LAB_3b405a2a:
  if (local_20 == 0) {
    _Flag = __stbuf(_File);
    local_20 = FUN_3b409c77(_File,(byte *)_Format,(localeinfo_struct *)0x0,(int **)&stack0x0000000c)
    ;
    __ftbuf(_Flag,_File);
  }
  FUN_3b405a67();
  return local_20;
}



void FUN_3b405a67(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



undefined ** FUN_3b405a71(void)

{
  return &PTR_DAT_3b4161a0;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_3b4161a0) || ((FILE *)&DAT_3b416400 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)(_File + -0x1da0b0d) >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    __lock(_Index + 0x10);
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) | 0x8000;
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)(s___AVtype_info___3b416190 + 0xf) < _File) && (_File < (FILE *)0x3b416401)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_3b40aa8c(((int)(_File + -0x1da0b0d) >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2010 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    FUN_3b40aa8c(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  _vscan_fn
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl _vscan_fn(undefined *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  size_t sVar2;
  undefined4 uVar3;
  int iVar4;
  char *unaff_ESI;
  size_t *psVar5;
  size_t local_20;
  undefined4 local_18;
  
  psVar5 = &local_20;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *psVar5 = 0;
    psVar5 = psVar5 + 1;
  }
  if ((unaff_ESI != (char *)0x0) && (param_2 != 0)) {
    sVar2 = _strlen(unaff_ESI);
    local_18 = 0x49;
    local_20 = 0x7fffffff;
    if (sVar2 < 0x80000000) {
      local_20 = sVar2;
    }
    uVar3 = (*(code *)param_1)(&stack0xffffffdc,param_2,param_3,param_4);
    return uVar3;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  FUN_3b408343();
  return 0xffffffff;
}



// Library Function - Multiple Matches With Different Base Names
//  _sscanf
//  _sscanf_s
// 
// Library: Visual Studio 2010 Release

int __cdecl FID_conflict__sscanf(char *_Src,char *_Format,...)

{
  int iVar1;
  
  iVar1 = _vscan_fn(__input_l,(int)_Format,0,&stack0x0000000c);
  return iVar1;
}



// Library Function - Single Match
//  __strnicmp_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __strnicmp_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if (_MaxCount == 0) {
    iVar2 = 0;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
    if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_3b408343();
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar2 = 0x7fffffff;
    }
    else if (_MaxCount < 0x80000000) {
      if ((local_14.locinfo)->lc_category[0].wlocale == (wchar_t *)0x0) {
        iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
      }
      else {
        iVar4 = (int)_Str1 - (int)_Str2;
        do {
          iVar2 = __tolower_l((uint)((byte *)_Str2)[iVar4],&local_14);
          iVar3 = __tolower_l((uint)(byte)*_Str2,&local_14);
          _Str2 = (char *)((byte *)_Str2 + 1);
          _MaxCount = _MaxCount - 1;
          if ((_MaxCount == 0) || (iVar2 == 0)) break;
        } while (iVar2 == iVar3);
        iVar2 = iVar2 - iVar3;
      }
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
    }
    else {
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_3b408343();
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar2 = 0x7fffffff;
    }
  }
  return iVar2;
}



// Library Function - Single Match
//  __strnicmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int *piVar1;
  int iVar2;
  
  if (DAT_3b417adc != 0) {
    iVar2 = __strnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
    return iVar2;
  }
  if (((_Str1 != (char *)0x0) && (_Str2 != (char *)0x0)) && (_MaxCount < 0x80000000)) {
    iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
    return iVar2;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  FUN_3b408343();
  return 0x7fffffff;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __CRT_INIT@12
// 
// Library: Visual Studio 2010 Release

undefined4 __CRT_INIT_12(undefined4 crtArgs,int dllState,int mainArgs)

{
  int initResult;
  _ptiddata threadData;
  code *pcVar1;
  DWORD threadId;
  
  if (dllState == 1) {
    initResult = __heap_init();
    if (initResult != 0) {
      initResult = __mtinit();
      if (initResult != 0) {
        __RTC_Initialize();
        commandLineArgs = GetCommandLineA();
        environmentStrings = ___crtGetEnvironmentStringsA();
        initResult = __ioinit();
        if (-1 < initResult) {
          initResult = __setargv();
          if (((-1 < initResult) && (initResult = __setenvp(), -1 < initResult)) &&
             (initResult = __cinit(0), initResult == 0)) {
            dllMainFlag = dllMainFlag + 1;
            return 1;
          }
          __ioterm();
        }
        __mtterm();
      }
      __heap_term();
    }
  }
  else if (dllState == 0) {
    if (0 < dllMainFlag) {
      dllMainFlag = dllMainFlag + -1;
      if (dllExitFlag == 0) {
        __cexit();
      }
      if (mainArgs == 0) {
        __ioterm();
        __mtterm();
        __heap_term();
      }
      performCleanup();
      return 1;
    }
  }
  else {
    if (dllState != 2) {
      if (dllState != 3) {
        return 1;
      }
      __freeptd((_ptiddata)0x0);
      return 1;
    }
    ___set_flsgetvalue();
    threadData = (_ptiddata)__calloc_crt(1,0x214);
    if (threadData != (_ptiddata)0x0) {
      pcVar1 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a70,dllMainFlag,threadData);
      initResult = (*pcVar1)();
      if (initResult != 0) {
        __initptd(threadData,(pthreadlocinfo)0x0);
        threadId = GetCurrentThreadId();
        threadData->_tid = threadId;
        threadData->_thandle = 0xffffffff;
        return 1;
      }
      _free(threadData);
    }
  }
  return 0;
}



void performCleanup(void)

{
  int basePointer;
  int registerEDI;
  
  if ((*(int *)(basePointer + 0x10) == registerEDI) && (dllMainFlag != -1)) {
    __mtterm();
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x3b405fe1)
// WARNING: Removing unreachable block (ram,0x3b405f8e)
// WARNING: Removing unreachable block (ram,0x3b40600e)
// Library Function - Single Match
//  ___DllMainCRTStartup
// 
// Library: Visual Studio 2010 Release

int __fastcall ___DllMainCRTStartup(int dllArgs,int dllState,undefined4 crtInitArgs)

{
  int initResult;
  int local_20;
  
  if (((dllState == 0) && (dllMainFlag == 0)) ||
     (((dllState == 1 || (dllState == 2)) &&
      (initResult = __CRT_INIT_12(crtInitArgs,dllState,dllArgs), initResult == 0)))) {
    local_20 = 0;
  }
  else {
    local_20 = performInitialization();
    if ((dllState == 1) && (local_20 == 0)) {
      performInitialization();
      __CRT_INIT_12(crtInitArgs,0,dllArgs);
    }
    if (((dllState == 0) || (dllState == 3)) &&
       (initResult = __CRT_INIT_12(crtInitArgs,dllState,dllArgs), initResult == 0)) {
      local_20 = 0;
    }
  }
  return local_20;
}



void entry(undefined4 mainArgs,int securityFlag,int dllMainArgs)

{
  if (securityFlag == 1) {
    ___security_init_cookie();
  }
  ___DllMainCRTStartup(dllMainArgs,securityFlag,mainArgs);
  return;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  errno_t eStack_10;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      iVar3 = (int)_Dst - (int)_Src;
      do {
        cVar1 = *_Src;
        _Src[iVar3] = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      piVar2 = __errno();
      eStack_10 = 0x22;
      *piVar2 = 0x22;
      goto LAB_3b406087;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_3b406087:
  FUN_3b408343();
  return eStack_10;
}



// Library Function - Single Match
//  _strlen
// 
// Library: Visual Studio

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
    if (cVar1 == '\0') goto LAB_3b406133;
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
LAB_3b406133:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  private: static void __cdecl type_info::_Type_info_dtor(class type_info *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl type_info::_Type_info_dtor(type_info *param_1)

{
  int *_Memory;
  int *piVar1;
  int *piVar2;
  
  __lock(0xe);
  _Memory = DAT_3b417434;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_3b417430;
    do {
      piVar2 = piVar1;
      if (DAT_3b417434 == (int *)0x0) goto LAB_3b40619f;
      piVar1 = DAT_3b417434;
    } while (*DAT_3b417434 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_3b417434[1];
    _free(_Memory);
LAB_3b40619f:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_3b4061c2();
  return;
}



void FUN_3b4061c2(void)

{
  FUN_3b40aa8c(0xe);
  return;
}



// Library Function - Single Match
//  _strcmp
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

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
      if (bVar4 != *_Str2) goto LAB_3b406214;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_3b4061e0;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_3b406214;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_3b406214;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_3b4061e0:
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
LAB_3b406214:
  return (uint)bVar5 * -2 + 1;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2010 Release

void __cdecl _abort(void)

{
  int iVar1;
  
  iVar1 = FUN_3b40c337();
  if (iVar1 != 0) {
    _raise(0x16);
  }
  if ((DAT_3b416420 & 2) != 0) {
    __call_reportfault(3,0x40000015,1);
  }
                    // WARNING: Subroutine does not return
  __exit(3);
}



// Library Function - Single Match
//  __GET_RTERRMSG
// 
// Library: Visual Studio 2010 Release

wchar_t * __cdecl __GET_RTERRMSG(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_3b4122c8)[uVar1 * 2]) {
      return (wchar_t *)(&PTR_u_R6002___floating_point_support_n_3b4122cc)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x16);
  return (wchar_t *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2010 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  wchar_t *pwVar1;
  int iVar2;
  errno_t eVar3;
  DWORD DVar4;
  size_t sVar5;
  HANDLE hFile;
  uint uVar6;
  wchar_t **lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  wchar_t *local_200;
  char local_1fc [500];
  uint local_8;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  pwVar1 = __GET_RTERRMSG(param_1);
  local_200 = pwVar1;
  if (pwVar1 != (wchar_t *)0x0) {
    iVar2 = __set_error_mode(3);
    if ((iVar2 == 1) || ((iVar2 = __set_error_mode(3), iVar2 == 0 && (DAT_3b41742c == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        uVar6 = 0;
        do {
          local_1fc[uVar6] = *(char *)(pwVar1 + uVar6);
          if (pwVar1[uVar6] == L'\0') break;
          uVar6 = uVar6 + 1;
        } while (uVar6 < 500);
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &local_200;
        local_1fc[499] = 0;
        sVar5 = _strlen(local_1fc);
        WriteFile(hFile,local_1fc,sVar5,(LPDWORD)lpNumberOfBytesWritten,lpOverlapped);
      }
    }
    else if (param_1 != 0xfc) {
      eVar3 = _wcscpy_s((wchar_t *)&DAT_3b417438,0x314,L"Runtime Error!\n\nProgram: ");
      if (eVar3 == 0) {
        _DAT_3b417672 = 0;
        DVar4 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_3b41746a,0x104);
        if ((DVar4 != 0) ||
           (eVar3 = _wcscpy_s((wchar_t *)&DAT_3b41746a,0x2fb,L"<program name unknown>"), eVar3 == 0)
           ) {
          sVar5 = _wcslen((wchar_t *)&DAT_3b41746a);
          if (0x3c < sVar5 + 1) {
            sVar5 = _wcslen((wchar_t *)&DAT_3b41746a);
            eVar3 = _wcsncpy_s((wchar_t *)((int)&DAT_3b4173f4 + sVar5 * 2),
                               0x2fb - ((int)(sVar5 * 2 + -0x76) >> 1),L"...",3);
            if (eVar3 != 0) goto LAB_3b406376;
          }
          eVar3 = _wcscat_s((wchar_t *)&DAT_3b417438,0x314,L"\n\n");
          if ((eVar3 == 0) &&
             (eVar3 = _wcscat_s((wchar_t *)&DAT_3b417438,0x314,local_200), eVar3 == 0)) {
            ___crtMessageBoxW((LPCWSTR)&DAT_3b417438,L"Microsoft Visual C++ Runtime Library",0x12010
                             );
            goto LAB_3b406451;
          }
        }
      }
LAB_3b406376:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
  }
LAB_3b406451:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2010 Release

void __cdecl __FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = __set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = __set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (DAT_3b41742c != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_3b406499(undefined4 param_1)

{
  _DAT_3b417a60 = param_1;
  return;
}



void __cdecl FUN_3b4064a8(undefined4 param_1)

{
  DAT_3b417a64 = param_1;
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2010 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a64);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



undefined4 * __thiscall FUN_3b4064ea(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_3b412440;
  FUN_3b404995((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_3b404a3d(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___TypeMatch
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl ___TypeMatch(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_3b406569:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_3b406548:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_3b406569;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_3b406548;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// Library Function - Single Match
//  ___FrameUnwindFilter
// 
// Library: Visual Studio 2010 Release

_ptiddata __cdecl ___FrameUnwindFilter(int **param_1)

{
  int iVar1;
  _ptiddata p_Var2;
  
  iVar1 = **param_1;
  if ((iVar1 == -0x1fbcbcae) || (iVar1 == -0x1fbcb0b3)) {
    p_Var2 = __getptd();
    if (0 < p_Var2->_ProcessingThrow) {
      p_Var2 = __getptd();
      p_Var2->_ProcessingThrow = p_Var2->_ProcessingThrow + -1;
    }
  }
  else if (iVar1 == -0x1f928c9d) {
    p_Var2 = __getptd();
    p_Var2->_ProcessingThrow = 0;
    terminate();
    return p_Var2;
  }
  return (_ptiddata)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___FrameUnwindToState
// 
// Library: Visual Studio 2010 Release

void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4)

{
  _ptiddata p_Var1;
  int iVar2;
  int iVar3;
  
  if (*(int *)(param_3 + 4) < 0x81) {
    iVar2 = (int)*(char *)(param_1 + 8);
  }
  else {
    iVar2 = *(int *)(param_1 + 8);
  }
  p_Var1 = __getptd();
  p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + 1;
  while (iVar3 = iVar2, iVar3 != param_4) {
    if ((iVar3 < 0) || (*(int *)(param_3 + 4) <= iVar3)) {
      _inconsistency();
    }
    iVar2 = *(int *)(*(int *)(param_3 + 8) + iVar3 * 8);
    if (*(int *)(*(int *)(param_3 + 8) + 4 + iVar3 * 8) != 0) {
      *(int *)(param_1 + 8) = iVar2;
      __CallSettingFrame_12(*(undefined4 *)(*(int *)(param_3 + 8) + 4 + iVar3 * 8),param_1,0x103);
    }
  }
  FUN_3b406681();
  if (iVar3 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar3;
  return;
}



void FUN_3b406681(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (0 < p_Var1->_ProcessingThrow) {
    p_Var1 = __getptd();
    p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + -1;
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___DestructExceptionObject
// 
// Library: Visual Studio 2010 Release

void __cdecl ___DestructExceptionObject(int *param_1)

{
  undefined *UNRECOVERED_JUMPTABLE;
  
  if ((((param_1 != (int *)0x0) && (*param_1 == -0x1f928c9d)) && (param_1[7] != 0)) &&
     (UNRECOVERED_JUMPTABLE = *(undefined **)(param_1[7] + 4),
     UNRECOVERED_JUMPTABLE != (undefined *)0x0)) {
    FID_conflict__CallMemberFunction1(param_1[6],UNRECOVERED_JUMPTABLE);
  }
  return;
}



// Library Function - Single Match
//  ___AdjustPointer
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl ___AdjustPointer(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = *param_2 + param_1;
  if (-1 < param_2[1]) {
    iVar1 = iVar1 + *(int *)(*(int *)(param_2[1] + param_1) + param_2[2]) + param_2[1];
  }
  return iVar1;
}



undefined __cdecl FUN_3b40675e(int param_1)

{
  int iVar1;
  byte *pbVar2;
  byte **ppbVar3;
  int *unaff_EDI;
  int local_10;
  int local_c;
  undefined local_5;
  
  local_10 = 0;
  if (unaff_EDI == (int *)0x0) {
    _inconsistency();
    terminate();
  }
  local_5 = (undefined)local_10;
  local_c = local_10;
  if (local_10 < *unaff_EDI) {
    do {
      ppbVar3 = *(byte ***)(*(int *)(param_1 + 0x1c) + 0xc);
      for (pbVar2 = *ppbVar3; ppbVar3 = ppbVar3 + 1, 0 < (int)pbVar2; pbVar2 = pbVar2 + -1) {
        iVar1 = ___TypeMatch((byte *)(unaff_EDI[1] + local_c),*ppbVar3,*(uint **)(param_1 + 0x1c));
        if (iVar1 != 0) {
          local_5 = 1;
          break;
        }
      }
      local_10 = local_10 + 1;
      local_c = local_c + 0x10;
    } while (local_10 < *unaff_EDI);
  }
  return local_5;
}



// WARNING: Function: __EH_prolog3_catch replaced with injection: EH_prolog3

void FUN_3b4067d4(void *param_1)

{
  code *pcVar1;
  _ptiddata p_Var2;
  
  p_Var2 = __getptd();
  if (p_Var2->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  unexpected();
  terminate();
  p_Var2 = __getptd();
  p_Var2->_curexcspec = param_1;
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  void * __cdecl CallCatchBlock(struct EHExceptionRecord *,struct EHRegistrationNode *,struct
// _CONTEXT *,struct _s_FuncInfo const *,void *,int,unsigned long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl
CallCatchBlock(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,
              _s_FuncInfo *param_4,void *param_5,int param_6,ulong param_7)

{
  _ptiddata p_Var1;
  void *in_ECX;
  undefined4 local_40 [2];
  undefined4 local_38;
  void *local_34;
  void *local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  void *local_20;
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_3b414180;
  uStack_c = 0x3b406829;
  local_38 = 0;
  local_28 = *(undefined4 *)(param_2 + -4);
  local_2c = __CreateFrameInfo(local_40,*(undefined4 *)(param_1 + 0x18));
  p_Var1 = __getptd();
  local_30 = p_Var1->_curexception;
  p_Var1 = __getptd();
  local_34 = p_Var1->_curcontext;
  p_Var1 = __getptd();
  p_Var1->_curexception = param_1;
  p_Var1 = __getptd();
  p_Var1->_curcontext = param_3;
  local_8 = (undefined *)0x1;
  local_20 = _CallCatchBlock2(param_2,param_4,in_ECX,(int)param_5,param_6);
  local_8 = (undefined *)0xfffffffe;
  FUN_3b406943();
  return local_20;
}



void FUN_3b406943(void)

{
  _ptiddata p_Var1;
  int iVar2;
  int unaff_EBP;
  int *unaff_ESI;
  int unaff_EDI;
  
  *(undefined4 *)(unaff_EDI + -4) = *(undefined4 *)(unaff_EBP + -0x24);
  __FindAndUnlinkFrame(*(void **)(unaff_EBP + -0x28));
  p_Var1 = __getptd();
  p_Var1->_curexception = *(void **)(unaff_EBP + -0x2c);
  p_Var1 = __getptd();
  p_Var1->_curcontext = *(void **)(unaff_EBP + -0x30);
  if ((((*unaff_ESI == -0x1f928c9d) && (unaff_ESI[4] == 3)) &&
      ((iVar2 = unaff_ESI[5], iVar2 == 0x19930520 ||
       ((iVar2 == 0x19930521 || (iVar2 == 0x19930522)))))) &&
     ((*(int *)(unaff_EBP + -0x34) == 0 && (*(int *)(unaff_EBP + -0x1c) != 0)))) {
    iVar2 = __IsExceptionObjectToBeDestroyed(unaff_ESI[6]);
    if (iVar2 != 0) {
      ___DestructExceptionObject(unaff_ESI);
    }
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___BuildCatchObjectHelper
// 
// Library: Visual Studio 2010 Release

char __cdecl ___BuildCatchObjectHelper(int param_1,int *param_2,uint *param_3,byte *param_4)

{
  int iVar1;
  void *pvVar2;
  size_t _Size;
  uint in_stack_ffffffd0;
  
  if (((param_3[1] == 0) || (*(char *)(param_3[1] + 8) == '\0')) ||
     ((param_3[2] == 0 && ((*param_3 & 0x80000000) == 0)))) {
    return '\0';
  }
  if (-1 < (int)*param_3) {
    param_2 = (int *)(param_3[2] + 0xc + (int)param_2);
  }
  if ((*param_3 & 8) == 0) {
    pvVar2 = *(void **)(param_1 + 0x18);
    if ((*param_4 & 1) == 0) {
      if (*(int *)(param_4 + 0x18) == 0) {
        iVar1 = _ValidateRead(pvVar2,1);
        if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
          _Size = *(size_t *)(param_4 + 0x14);
          pvVar2 = (void *)___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
          FID_conflict__memcpy(param_2,pvVar2,_Size);
          return '\0';
        }
      }
      else {
        iVar1 = _ValidateRead(pvVar2,1);
        if (((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) &&
           (iVar1 = _ValidateRead(*(void **)(param_4 + 0x18),in_stack_ffffffd0), iVar1 != 0)) {
          return ((*param_4 & 4) != 0) + '\x01';
        }
      }
    }
    else {
      iVar1 = _ValidateRead(pvVar2,1);
      if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
        FID_conflict__memcpy(param_2,*(void **)(param_1 + 0x18),*(size_t *)(param_4 + 0x14));
        if (*(int *)(param_4 + 0x14) != 4) {
          return '\0';
        }
        iVar1 = *param_2;
        if (iVar1 == 0) {
          return '\0';
        }
        goto LAB_3b406a3e;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_3b406a3e:
      iVar1 = ___AdjustPointer(iVar1,(int *)(param_4 + 8));
      *param_2 = iVar1;
      return '\0';
    }
  }
  _inconsistency();
  return '\0';
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___BuildCatchObject
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___BuildCatchObject(int param_1,int *param_2,uint *param_3,byte *param_4)

{
  char cVar1;
  undefined3 extraout_var;
  int *piVar2;
  
  piVar2 = param_2;
  if ((*param_3 & 0x80000000) == 0) {
    piVar2 = (int *)(param_3[2] + 0xc + (int)param_2);
  }
  cVar1 = ___BuildCatchObjectHelper(param_1,param_2,param_3,param_4);
  if (CONCAT31(extraout_var,cVar1) == 1) {
    ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    FID_conflict__CallMemberFunction1(piVar2,*(undefined **)(param_4 + 0x18));
  }
  else if (CONCAT31(extraout_var,cVar1) == 2) {
    ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    FID_conflict__CallMemberFunction1(piVar2,*(undefined **)(param_4 + 0x18));
  }
  return;
}



// Library Function - Single Match
//  void __cdecl CatchIt(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const
// *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char)
// 
// Library: Visual Studio 2010 Release

void __cdecl
CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
       _s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,
       _s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11)

{
  void *pvVar1;
  uint *unaff_EBX;
  int *unaff_ESI;
  int *unaff_EDI;
  int *piVar2;
  
  if (param_5 != (_s_FuncInfo *)0x0) {
    ___BuildCatchObject((int)param_1,unaff_ESI,unaff_EBX,(byte *)param_5);
  }
  if (param_7 == (_s_CatchableType *)0x0) {
    param_7 = (_s_CatchableType *)unaff_ESI;
  }
  _UnwindNestedFrames((EHRegistrationNode *)param_7,param_1);
  piVar2 = unaff_ESI;
  ___FrameUnwindToState((int)unaff_ESI,param_3,(int)param_4,*unaff_EDI);
  unaff_ESI[2] = unaff_EDI[1] + 1;
  pvVar1 = CallCatchBlock(param_1,(EHRegistrationNode *)unaff_ESI,(_CONTEXT *)param_2,
                          (_s_FuncInfo *)param_4,param_6,0x100,(ulong)piVar2);
  if (pvVar1 != (void *)0x0) {
    _JumpToContinuation(pvVar1,(EHRegistrationNode *)unaff_ESI);
  }
  return;
}



// Library Function - Single Match
//  void __cdecl FindHandlerForForeignException(struct EHExceptionRecord *,struct EHRegistrationNode
// *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2010 Release

void __cdecl
FindHandlerForForeignException
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8)

{
  _ptiddata p_Var1;
  void *pvVar2;
  int iVar3;
  _s_TryBlockMapEntry *p_Var4;
  int *piVar5;
  int iVar6;
  _s_TryBlockMapEntry *unaff_EBX;
  EHRegistrationNode *unaff_ESI;
  int unaff_EDI;
  uint in_stack_fffffff0;
  uint local_8;
  
  if (*(int *)param_1 != -0x7ffffffd) {
    p_Var1 = __getptd();
    if (p_Var1->_translator != (void *)0x0) {
      p_Var1 = __getptd();
      pvVar2 = (void *)FUN_3b4071c6();
      if ((((p_Var1->_translator != pvVar2) && (*(int *)param_1 != -0x1fbcb0b3)) &&
          (*(int *)param_1 != -0x1fbcbcae)) &&
         (iVar3 = _CallSETranslator(param_1,param_2,param_3,param_4,param_5,param_7,param_8),
         iVar3 != 0)) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      _inconsistency();
    }
    p_Var4 = _GetRangeOfTrysToCheck(param_5,param_7,param_6,&local_8,(uint *)&stack0xfffffff0);
    if (local_8 < in_stack_fffffff0) {
      piVar5 = (int *)(p_Var4 + 0xc);
      do {
        if ((piVar5[-3] <= param_6) && (param_6 <= piVar5[-2])) {
          iVar6 = *piVar5 * 0x10 + piVar5[1];
          iVar3 = *(int *)(iVar6 + -0xc);
          if (((iVar3 == 0) || (*(char *)(iVar3 + 8) == '\0')) &&
             ((*(byte *)(iVar6 + -0x10) & 0x40) == 0)) {
            CatchIt(param_1,(EHRegistrationNode *)param_3,(_CONTEXT *)param_4,param_5,
                    (_s_FuncInfo *)0x0,(_s_HandlerType *)param_7,(_s_CatchableType *)param_8,
                    unaff_EBX,unaff_EDI,unaff_ESI,(uchar)in_stack_fffffff0);
          }
        }
        local_8 = local_8 + 1;
        piVar5 = piVar5 + 5;
      } while (local_8 < in_stack_fffffff0);
    }
  }
  return;
}



// Library Function - Single Match
//  void __cdecl FindHandler(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,unsigned char,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2010 Release

void __cdecl
FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
           _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  int *piVar1;
  _s_FuncInfo *p_Var2;
  byte **ppbVar3;
  char cVar4;
  bool bVar5;
  _ptiddata p_Var6;
  int iVar7;
  _s_TryBlockMapEntry *p_Var8;
  EHRegistrationNode *unaff_EBX;
  _s_FuncInfo *p_Var9;
  _s_FuncInfo *p_Var10;
  _s_FuncInfo **pp_Var11;
  int unaff_ESI;
  int *piVar12;
  _s_TryBlockMapEntry *unaff_EDI;
  byte **ppbVar13;
  uint *puVar14;
  EHRegistrationNode *pEVar15;
  undefined **in_stack_ffffffc8;
  uint local_24;
  byte **local_20;
  byte *local_1c;
  _s_FuncInfo *local_18;
  uint local_14;
  byte *local_10;
  int local_c;
  char local_5;
  
  p_Var10 = param_5;
  local_5 = '\0';
  if (*(int *)(param_5 + 4) < 0x81) {
    local_c = (int)(char)param_2[8];
  }
  else {
    local_c = *(int *)(param_2 + 8);
  }
  if ((local_c < -1) || (*(int *)(param_5 + 4) <= local_c)) {
    _inconsistency();
  }
  piVar12 = (int *)param_1;
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_3b407070;
  p_Var9 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_3b406ec0;
  iVar7 = *(int *)(param_1 + 0x14);
  if (((iVar7 != 0x19930520) && (iVar7 != 0x19930521)) && (iVar7 != 0x19930522)) goto LAB_3b406ec0;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_3b406ec0;
  p_Var6 = __getptd();
  if (p_Var6->_curexception != (void *)0x0) {
    p_Var6 = __getptd();
    piVar12 = (int *)p_Var6->_curexception;
    param_1 = (EHExceptionRecord *)piVar12;
    p_Var6 = __getptd();
    param_3 = (_CONTEXT *)p_Var6->_curcontext;
    iVar7 = _ValidateRead(piVar12,1);
    if (iVar7 == 0) {
      _inconsistency();
    }
    if ((((*piVar12 == -0x1f928c9d) && (piVar12[4] == 3)) &&
        ((iVar7 = piVar12[5], iVar7 == 0x19930520 ||
         ((iVar7 == 0x19930521 || (iVar7 == 0x19930522)))))) && (piVar12[7] == 0)) {
      _inconsistency();
    }
    p_Var6 = __getptd();
    if (p_Var6->_curexcspec == (void *)0x0) goto LAB_3b406ec0;
    p_Var6 = __getptd();
    piVar1 = (int *)p_Var6->_curexcspec;
    p_Var6 = __getptd();
    iVar7 = 0;
    p_Var6->_curexcspec = (void *)0x0;
    cVar4 = FUN_3b40675e((int)param_1);
    piVar12 = (int *)param_1;
    if (cVar4 != '\0') goto LAB_3b406ec0;
    p_Var10 = (_s_FuncInfo *)0x0;
    if (0 < *piVar1) {
      do {
        bVar5 = type_info::operator==
                          (*(type_info **)(p_Var10 + piVar1[1] + 4),
                           (type_info *)&PTR_PTR__scalar_deleting_destructor__3b416424);
        if (bVar5) goto LAB_3b406e84;
        iVar7 = iVar7 + 1;
        p_Var10 = p_Var10 + 0x10;
      } while (iVar7 < *piVar1);
    }
    do {
      terminate();
LAB_3b406e84:
      ___DestructExceptionObject((int *)param_1);
      param_1 = (EHExceptionRecord *)0x3b412448;
      std::exception::exception((exception *)&stack0xffffffc8,(char **)&param_1);
      in_stack_ffffffc8 = &PTR_FUN_3b412440;
      __CxxThrowException_8(&stack0xffffffc8,&DAT_3b4141e4);
      p_Var9 = p_Var10;
      piVar12 = (int *)param_1;
LAB_3b406ec0:
      puVar14 = (uint *)param_5;
      p_Var10 = param_5;
      if (((*piVar12 == -0x1f928c9d) && (piVar12[4] == 3)) &&
         ((p_Var2 = (_s_FuncInfo *)piVar12[5], p_Var2 == p_Var9 ||
          ((p_Var2 == (_s_FuncInfo *)0x19930521 || (p_Var2 == (_s_FuncInfo *)0x19930522)))))) {
        if ((*(int *)(param_5 + 0xc) != 0) &&
           (p_Var8 = _GetRangeOfTrysToCheck(param_5,param_7,local_c,&local_14,&local_24),
           local_14 < local_24)) {
          ppbVar13 = (byte **)(p_Var8 + 0x10);
          do {
            local_20 = ppbVar13;
            if (((int)ppbVar13[-4] <= local_c) && (local_c <= (int)ppbVar13[-3])) {
              local_10 = *ppbVar13;
              ppbVar3 = ppbVar13;
              for (local_1c = ppbVar13[-1]; local_20 = ppbVar13, 0 < (int)local_1c;
                  local_1c = local_1c + -1) {
                pp_Var11 = *(_s_FuncInfo ***)(piVar12[7] + 0xc);
                local_20 = ppbVar3;
                for (local_18 = *pp_Var11; 0 < (int)local_18; local_18 = local_18 + -1) {
                  pp_Var11 = pp_Var11 + 1;
                  p_Var10 = *pp_Var11;
                  iVar7 = ___TypeMatch(local_10,(byte *)p_Var10,(uint *)piVar12[7]);
                  if (iVar7 != 0) {
                    local_5 = '\x01';
                    CatchIt((EHExceptionRecord *)piVar12,(EHRegistrationNode *)param_3,
                            (_CONTEXT *)param_4,param_5,p_Var10,(_s_HandlerType *)param_7,
                            (_s_CatchableType *)param_8,unaff_EDI,unaff_ESI,unaff_EBX,
                            (uchar)SUB41(in_stack_ffffffc8,0));
                    piVar12 = (int *)param_1;
                    goto LAB_3b406fbc;
                  }
                }
                local_10 = local_10 + 0x10;
                ppbVar3 = local_20;
              }
            }
LAB_3b406fbc:
            local_14 = local_14 + 1;
            ppbVar13 = local_20 + 5;
            puVar14 = (uint *)param_5;
            local_20 = ppbVar13;
          } while (local_14 < local_24);
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject(piVar12);
        }
        if ((((local_5 != '\0') || ((*puVar14 & 0x1fffffff) < 0x19930521)) || (puVar14[7] == 0)) ||
           (cVar4 = FUN_3b40675e((int)piVar12), cVar4 != '\0')) goto LAB_3b40709c;
        __getptd();
        __getptd();
        p_Var6 = __getptd();
        p_Var6->_curexception = piVar12;
        p_Var6 = __getptd();
        p_Var6->_curcontext = param_3;
        pEVar15 = param_8;
        if (param_8 == (EHRegistrationNode *)0x0) {
          pEVar15 = param_2;
        }
        _UnwindNestedFrames(pEVar15,(EHExceptionRecord *)piVar12);
        piVar12 = (int *)param_5;
        ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
        FUN_3b4067d4(*(void **)((int)piVar12 + 0x1c));
        p_Var10 = param_5;
      }
LAB_3b407070:
      if (*(int *)(p_Var10 + 0xc) == 0) goto LAB_3b40709c;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)piVar12,param_2,param_3,param_4,p_Var10,local_c,param_7,param_8)
    ;
LAB_3b40709c:
    p_Var6 = __getptd();
    if (p_Var6->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_3b4070b4(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_3b412440;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl
___InternalCxxFrameHandler
          (int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,uint *param_5,
          int param_6,EHRegistrationNode *param_7,uchar param_8)

{
  _ptiddata p_Var1;
  undefined4 uVar2;
  
  p_Var1 = __getptd();
  if ((((*(int *)((p_Var1->_setloc_data)._cacheout + 0x27) != 0) || (*param_1 == -0x1f928c9d)) ||
      (*param_1 == -0x7fffffda)) ||
     (((*param_5 & 0x1fffffff) < 0x19930522 || ((*(byte *)(param_5 + 8) & 1) == 0)))) {
    if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
      if ((param_5[3] != 0) || ((0x19930520 < (*param_5 & 0x1fffffff) && (param_5[7] != 0)))) {
        if ((*param_1 == -0x1f928c9d) &&
           (((2 < (uint)param_1[4] && (0x19930522 < (uint)param_1[5])) &&
            (*(code **)(param_1[7] + 8) != (code *)0x0)))) {
          uVar2 = (**(code **)(param_1[7] + 8))
                            (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          return uVar2;
        }
        FindHandler((EHExceptionRecord *)param_1,param_2,param_3,param_4,(_s_FuncInfo *)param_5,
                    param_8,param_6,param_7);
      }
    }
    else if ((param_5[1] != 0) && (param_6 == 0)) {
      ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
    }
  }
  return 1;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == securityCookie) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



void FUN_3b4071c6(void)

{
  (*(code *)PTR_FUN_3b416000)(0);
  return;
}



// Library Function - Single Match
//  ___set_flsgetvalue
// 
// Library: Visual Studio 2010 Release

LPVOID ___set_flsgetvalue(void)

{
  LPVOID lpTlsValue;
  
  lpTlsValue = TlsGetValue(dwTlsIndex_3b416448);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)(*(code *)PTR_FUN_3b416004)(lpTlsValue_3b417a6c);
    TlsSetValue(dwTlsIndex_3b416448,lpTlsValue);
  }
  return lpTlsValue;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 2010 Release

void __cdecl __mtterm(void)

{
  code *pcVar1;
  
  if (dllMainFlag != -1) {
    pcVar1 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a74,dllMainFlag);
    (*pcVar1)();
    dllMainFlag = -1;
  }
  if (dwTlsIndex_3b416448 != 0xffffffff) {
    TlsFree(dwTlsIndex_3b416448);
    dwTlsIndex_3b416448 = 0xffffffff;
  }
  __mtdeletelocks();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __initptd
// 
// Library: Visual Studio 2010 Release

void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale)

{
  GetModuleHandleW(L"KERNEL32.DLL");
  _Ptd->_pxcptacttab = &DAT_3b412908;
  _Ptd->_terrno = 0;
  _Ptd->_holdrand = 1;
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&lpAddend_3b416610;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_3b4072eb();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_3b416d78;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_3b4072f4();
  return;
}



void FUN_3b4072eb(void)

{
  FUN_3b40aa8c(0xd);
  return;
}



void FUN_3b4072f4(void)

{
  FUN_3b40aa8c(0xc);
  return;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2010 Release

_ptiddata __cdecl __getptd_noexit(void)

{
  DWORD dwErrCode;
  code *pcVar1;
  _ptiddata _Ptd;
  int iVar2;
  DWORD DVar3;
  undefined4 uVar4;
  
  dwErrCode = GetLastError();
  uVar4 = dllMainFlag;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      pcVar1 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a70,dllMainFlag,_Ptd);
      iVar2 = (*pcVar1)();
      if (iVar2 == 0) {
        _free(_Ptd);
        _Ptd = (_ptiddata)0x0;
      }
      else {
        __initptd(_Ptd,(pthreadlocinfo)0x0);
        DVar3 = GetCurrentThreadId();
        _Ptd->_thandle = 0xffffffff;
        _Ptd->_tid = DVar3;
      }
    }
  }
  SetLastError(dwErrCode);
  return _Ptd;
}



// Library Function - Single Match
//  __getptd
// 
// Library: Visual Studio 2010 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __freefls@4
// 
// Library: Visual Studio 2010 Release

void __freefls_4(void *param_1)

{
  LONG **lpAddend;
  LONG *pLVar1;
  LONG LVar2;
  
  if (param_1 != (void *)0x0) {
    if (*(void **)((int)param_1 + 0x24) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x24));
    }
    if (*(void **)((int)param_1 + 0x2c) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x2c));
    }
    if (*(void **)((int)param_1 + 0x34) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x34));
    }
    if (*(void **)((int)param_1 + 0x3c) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x3c));
    }
    if (*(void **)((int)param_1 + 0x40) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x40));
    }
    if (*(void **)((int)param_1 + 0x44) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x44));
    }
    if (*(void **)((int)param_1 + 0x48) != (void *)0x0) {
      _free(*(void **)((int)param_1 + 0x48));
    }
    if (*(undefined **)((int)param_1 + 0x5c) != &DAT_3b412908) {
      _free(*(undefined **)((int)param_1 + 0x5c));
    }
    __lock(0xd);
    lpAddend = *(LONG ***)((int)param_1 + 0x68);
    if (lpAddend != (LONG **)0x0) {
      LVar2 = InterlockedDecrement((LONG *)lpAddend);
      if ((LVar2 == 0) && (lpAddend != &lpAddend_3b416610)) {
        _free(lpAddend);
      }
    }
    FUN_3b4074aa();
    __lock(0xc);
    pLVar1 = *(LONG **)((int)param_1 + 0x6c);
    if (pLVar1 != (LONG *)0x0) {
      ___removelocaleref(pLVar1);
      if (((pLVar1 != (LONG *)PTR_DAT_3b416d78) && (pLVar1 != (LONG *)&DAT_3b416ca0)) &&
         (*pLVar1 == 0)) {
        ___freetlocinfo(pLVar1);
      }
    }
    FUN_3b4074b6();
    _free(param_1);
  }
  return;
}



void FUN_3b4074aa(void)

{
  FUN_3b40aa8c(0xd);
  return;
}



void FUN_3b4074b6(void)

{
  FUN_3b40aa8c(0xc);
  return;
}



// Library Function - Single Match
//  __freeptd
// 
// Library: Visual Studio 2010 Release

void __cdecl __freeptd(_ptiddata _Ptd)

{
  LPVOID pvVar1;
  code *pcVar2;
  int iVar3;
  
  if (dllMainFlag != -1) {
    if ((_Ptd == (_ptiddata)0x0) &&
       (pvVar1 = TlsGetValue(dwTlsIndex_3b416448), pvVar1 != (LPVOID)0x0)) {
      iVar3 = dllMainFlag;
      pcVar2 = (code *)TlsGetValue(dwTlsIndex_3b416448);
      _Ptd = (_ptiddata)(*pcVar2)(iVar3);
    }
    pcVar2 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a70,dllMainFlag,0);
    (*pcVar2)();
    __freefls_4(_Ptd);
  }
  if (dwTlsIndex_3b416448 != 0xffffffff) {
    TlsSetValue(dwTlsIndex_3b416448,(LPVOID)0x0);
  }
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinit(void)

{
  undefined *puVar1;
  HMODULE hModule;
  BOOL BVar2;
  int iVar3;
  code *pcVar4;
  _ptiddata _Ptd;
  DWORD DVar5;
  
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if (hModule == (HMODULE)0x0) {
    __mtterm();
    return 0;
  }
  DAT_3b417a68 = GetProcAddress(hModule,"FlsAlloc");
  lpTlsValue_3b417a6c = GetProcAddress(hModule,"FlsGetValue");
  DAT_3b417a70 = GetProcAddress(hModule,"FlsSetValue");
  DAT_3b417a74 = GetProcAddress(hModule,"FlsFree");
  if ((((DAT_3b417a68 == (FARPROC)0x0) || (lpTlsValue_3b417a6c == (LPVOID)0x0)) ||
      (DAT_3b417a70 == (FARPROC)0x0)) || (DAT_3b417a74 == (FARPROC)0x0)) {
    lpTlsValue_3b417a6c = TlsGetValue_exref;
    DAT_3b417a68 = (FARPROC)&LAB_3b4071cf;
    DAT_3b417a70 = TlsSetValue_exref;
    DAT_3b417a74 = TlsFree_exref;
  }
  dwTlsIndex_3b416448 = TlsAlloc();
  if ((dwTlsIndex_3b416448 != 0xffffffff) &&
     (BVar2 = TlsSetValue(dwTlsIndex_3b416448,lpTlsValue_3b417a6c), BVar2 != 0)) {
    __init_pointers();
    puVar1 = PTR_FUN_3b416000;
    DAT_3b417a68 = (FARPROC)(*(code *)PTR_FUN_3b416000)(DAT_3b417a68);
    lpTlsValue_3b417a6c = (LPVOID)(*(code *)puVar1)(lpTlsValue_3b417a6c);
    DAT_3b417a70 = (FARPROC)(*(code *)puVar1)(DAT_3b417a70);
    DAT_3b417a74 = (FARPROC)(*(code *)puVar1)(DAT_3b417a74);
    iVar3 = __mtinitlocks();
    puVar1 = PTR_FUN_3b416004;
    if (iVar3 != 0) {
      pcVar4 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a68,__freefls_4);
      dllMainFlag = (*pcVar4)();
      if ((dllMainFlag != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        pcVar4 = (code *)(*(code *)puVar1)(DAT_3b417a70,dllMainFlag,_Ptd);
        iVar3 = (*pcVar4)();
        if (iVar3 != 0) {
          __initptd(_Ptd,(pthreadlocinfo)0x0);
          DVar5 = GetCurrentThreadId();
          _Ptd->_thandle = 0xffffffff;
          _Ptd->_tid = DVar5;
          return 1;
        }
      }
    }
    __mtterm();
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl terminate(void)
// 
// Library: Visual Studio 2010 Release

void __cdecl terminate(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_terminate != (code *)0x0) {
    (*(code *)p_Var1->_terminate)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  void __cdecl unexpected(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl unexpected(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_unexpected != (code *)0x0) {
    (*(code *)p_Var1->_unexpected)();
  }
  terminate();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl _inconsistency(void)
// 
// Library: Visual Studio 2010 Release

void __cdecl _inconsistency(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417a78);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
  }
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_3b40772c(void)

{
  DAT_3b417a78 = (*(code *)PTR_FUN_3b416000)(terminate);
  return;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Library: Visual Studio 2010 Release

void __CallSettingFrame_12(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)__NLG_Notify1(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  __NLG_Notify1(param_3);
  return;
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2010 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_3b416460)[uVar1 * 2]) {
      return (&DAT_3b416464)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



// Library Function - Single Match
//  __errno
// 
// Library: Visual Studio 2010 Release

int * __cdecl __errno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (int *)&DAT_3b4165c8;
  }
  return &p_Var1->_terrno;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2010 Release

ulong * __cdecl ___doserrno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (ulong *)&DAT_3b4165cc;
  }
  return &p_Var1->_tdoserrno;
}



// Library Function - Single Match
//  __dosmaperr
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __dosmaperr(ulong param_1)

{
  ulong *puVar1;
  int iVar2;
  int *piVar3;
  
  puVar1 = ___doserrno();
  *puVar1 = param_1;
  iVar2 = __get_errno_from_oserr(param_1);
  piVar3 = __errno();
  *piVar3 = iVar2;
  return;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2010 Release

int __cdecl __heap_init(void)

{
  hHeap_3b417a7c = HeapCreate(0,0x1000,0);
  return (uint)(hHeap_3b417a7c != (HANDLE)0x0);
}



// Library Function - Single Match
//  __heap_term
// 
// Library: Visual Studio 2010 Release

void __cdecl __heap_term(void)

{
  HeapDestroy(hHeap_3b417a7c);
  hHeap_3b417a7c = (HANDLE)0x0;
  return;
}



// Library Function - Single Match
//  ___crtCorExitProcess
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___crtCorExitProcess(int param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(L"mscoree.dll");
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"CorExitProcess");
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtExitProcess
// 
// Library: Visual Studio 2010 Release

void __cdecl ___crtExitProcess(int param_1)

{
  ___crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_3b40788c(void)

{
  __lock(8);
  return;
}



void FUN_3b407895(void)

{
  FUN_3b40aa8c(8);
  return;
}



// Library Function - Single Match
//  __init_pointers
// 
// Library: Visual Studio 2010 Release

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_3b4071c6();
  FUN_3b4064a8(uVar1);
  FUN_3b4081b9(uVar1);
  FUN_3b406499(uVar1);
  FUN_3b40ce67(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_3b40772c();
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2010 Release

void __cdecl __initterm_e(undefined **param_1,undefined **param_2)

{
  int iVar1;
  
  iVar1 = 0;
  while ((param_1 < param_2 && (iVar1 == 0))) {
    if ((code *)*param_1 != (code *)0x0) {
      iVar1 = (*(code *)*param_1)();
    }
    param_1 = (code **)param_1 + 1;
  }
  return;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  code **ppcVar3;
  
  if ((DAT_3b418210 != (code *)0x0) &&
     (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_3b418210), BVar1 != 0)) {
    (*DAT_3b418210)(param_1);
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_3b411150,(undefined **)&DAT_3b411164);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_3b40c0b1);
    ppcVar3 = (code **)&DAT_3b411148;
    do {
      if (*ppcVar3 != (code *)0x0) {
        (**ppcVar3)();
      }
      ppcVar3 = ppcVar3 + 1;
    } while (ppcVar3 < &DAT_3b41114c);
    if ((DAT_3b418214 != (code *)0x0) &&
       (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_3b418214), BVar1 != 0)) {
      (*DAT_3b418214)(0,2,0);
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x3b407abd)
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2010 Release

void __cdecl _doexit(int param_1,int param_2,int param_3)

{
  undefined *puVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  code *pcVar5;
  int *piVar6;
  int *piVar7;
  int *local_34;
  int *local_2c;
  int *local_28;
  code **local_24;
  code **local_20;
  
  __lock(8);
  puVar1 = PTR_FUN_3b416004;
  if (DAT_3b417ab0 != 1) {
    dllExitFlag = 1;
    DAT_3b417aa8 = (undefined)param_3;
    if (param_2 == 0) {
      piVar2 = (int *)(*(code *)PTR_FUN_3b416004)(DAT_3b418208);
      if (piVar2 != (int *)0x0) {
        piVar3 = (int *)(*(code *)puVar1)(DAT_3b418204);
        local_34 = piVar2;
        local_2c = piVar3;
        local_28 = piVar2;
        while (piVar3 = piVar3 + -1, piVar2 <= piVar3) {
          iVar4 = FUN_3b4071c6();
          if (*piVar3 != iVar4) {
            if (piVar3 < piVar2) break;
            pcVar5 = (code *)(*(code *)puVar1)(*piVar3);
            iVar4 = FUN_3b4071c6();
            *piVar3 = iVar4;
            (*pcVar5)();
            piVar6 = (int *)(*(code *)puVar1)(DAT_3b418208);
            piVar7 = (int *)(*(code *)puVar1)(DAT_3b418204);
            if ((local_28 != piVar6) || (piVar2 = local_34, local_2c != piVar7)) {
              piVar2 = piVar6;
              piVar3 = piVar7;
              local_34 = piVar6;
              local_2c = piVar7;
              local_28 = piVar6;
            }
          }
        }
      }
      for (local_20 = (code **)&DAT_3b411168; local_20 < &DAT_3b411174; local_20 = local_20 + 1) {
        if (*local_20 != (code *)0x0) {
          (**local_20)();
        }
      }
    }
    for (local_24 = (code **)&DAT_3b411178; local_24 < &DAT_3b41117c; local_24 = local_24 + 1) {
      if (*local_24 != (code *)0x0) {
        (**local_24)();
      }
    }
  }
  FUN_3b407ab7();
  if (param_3 == 0) {
    DAT_3b417ab0 = 1;
    FUN_3b40aa8c(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_3b407ab7(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_3b40aa8c(8);
  }
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2010 Release

void __cdecl __exit(int _Code)

{
  _doexit(_Code,1,0);
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2010 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2010 Release

void __cdecl __amsg_exit(int param_1)

{
  __FF_MSGBANNER();
  __NMSG_WRITE(param_1);
                    // WARNING: Subroutine does not return
  __exit(0xff);
}



// Library Function - Single Match
//  __malloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __malloc_crt(size_t _Size)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = _malloc(_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_3b417ab8 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_3b417ab8 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __calloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __calloc_crt(size_t _Count,size_t _Size)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = __calloc_impl(_Count,_Size,(undefined4 *)0x0);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_3b417ab8 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_3b417ab8 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __realloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __realloc_crt(void *_Ptr,size_t _NewSize)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = _realloc(_Ptr,_NewSize);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_NewSize == 0) {
      return (void *)0x0;
    }
    if (DAT_3b417ab8 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_3b417ab8 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __recalloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __recalloc_crt(void *_Ptr,size_t _Count,size_t _Size)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = __recalloc(_Ptr,_Count,_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_Size == 0) {
      return (void *)0x0;
    }
    if (DAT_3b417ab8 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_3b417ab8 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 2010 Release

size_t __cdecl __msize(void *_Memory)

{
  int *piVar1;
  SIZE_T SVar2;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    return 0xffffffff;
  }
  SVar2 = HeapSize(hHeap_3b417a7c,0,_Memory);
  return SVar2;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Library: Visual Studio

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  int *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = securityCookie ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Library: Visual Studio

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  
  *unaff_FS_OFFSET = unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __except_handler4
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl __except_handler4(PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  BOOL BVar3;
  PVOID pvVar4;
  int *piVar5;
  PEXCEPTION_RECORD local_1c;
  undefined4 local_18;
  PVOID *local_14;
  undefined4 local_10;
  PVOID local_c;
  char local_5;
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ securityCookie);
  local_5 = '\0';
  local_10 = 1;
  iVar1 = (int)param_2 + 0x10;
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  pvVar4 = param_2;
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    *(PEXCEPTION_RECORD **)((int)param_2 + -4) = &local_1c;
    pvVar4 = *(PVOID *)((int)param_2 + 0xc);
    local_1c = param_1;
    local_18 = param_3;
    if (pvVar4 == (PVOID)0xfffffffe) {
      return local_10;
    }
    do {
      local_14 = (PVOID *)(piVar5 + (int)pvVar4 * 3 + 4);
      local_c = *local_14;
      if ((undefined *)piVar5[(int)pvVar4 * 3 + 5] != (undefined *)0x0) {
        iVar2 = __EH4_CallFilterFunc_8((undefined *)piVar5[(int)pvVar4 * 3 + 5]);
        local_5 = '\x01';
        if (iVar2 < 0) {
          local_10 = 0;
          goto LAB_3b407d88;
        }
        if (0 < iVar2) {
          if ((param_1->ExceptionCode == 0xe06d7363) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_3b412438)
             , BVar3 != 0)) {
            ___DestructExceptionObject((int *)param_1);
          }
          __EH4_GlobalUnwind2_8(param_2,param_1);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&securityCookie);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_3b407e4f;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_3b407e4f:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&securityCookie);
  }
LAB_3b407d88:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
}



// Library Function - Single Match
//  __close_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __close_nolock(int _FileHandle)

{
  intptr_t iVar1;
  intptr_t iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  int iVar5;
  
  iVar1 = __get_osfhandle(_FileHandle);
  if (iVar1 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_3b418100 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_3b418100 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_3b407ed5;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_3b407ed7;
    }
  }
LAB_3b407ed5:
  DVar4 = 0;
LAB_3b407ed7:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
  if (DVar4 == 0) {
    iVar5 = 0;
  }
  else {
    __dosmaperr(DVar4);
    iVar5 = -1;
  }
  return iVar5;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __close
// 
// Library: Visual Studio 2010 Release

int __cdecl __close(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_3b407fc7();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_3b408343();
  }
  return -1;
}



void FUN_3b407fc7(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2010 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    return -1;
  }
  return _File->_file;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((_File->_flag & 0x83U) != 0) && ((_File->_flag & 8U) != 0)) {
    _free(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



// Library Function - Single Match
//  __flush
// 
// Library: Visual Studio 2010 Release

int __cdecl __flush(FILE *_File)

{
  int _FileHandle;
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *_Buf;
  
  iVar2 = 0;
  if ((((byte)_File->_flag & 3) == 2) && ((_File->_flag & 0x108U) != 0)) {
    _Buf = _File->_base;
    uVar3 = (int)_File->_ptr - (int)_Buf;
    if (0 < (int)uVar3) {
      uVar1 = uVar3;
      _FileHandle = __fileno(_File);
      uVar1 = __write(_FileHandle,_Buf,uVar1);
      if (uVar1 == uVar3) {
        if ((char)_File->_flag < '\0') {
          _File->_flag = _File->_flag & 0xfffffffd;
        }
      }
      else {
        _File->_flag = _File->_flag | 0x20;
        iVar2 = -1;
      }
    }
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return iVar2;
}



// Library Function - Single Match
//  __fflush_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  
  if (_File == (FILE *)0x0) {
    iVar1 = _flsall(0);
  }
  else {
    iVar1 = __flush(_File);
    if (iVar1 == 0) {
      if ((_File->_flag & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = __fileno(_File);
        iVar1 = __commit(iVar1);
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _flsall
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _flsall(int param_1)

{
  void **ppvVar1;
  void *_File;
  FILE *_File_00;
  int iVar2;
  int _Index;
  int local_28;
  int local_20;
  
  local_20 = 0;
  local_28 = 0;
  __lock(1);
  for (_Index = 0; _Index < DAT_3b419220; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_3b41821c + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_3b41821c + _Index * 4);
      if ((_File_00->_flag & 0x83U) != 0) {
        if (param_1 == 1) {
          iVar2 = __fflush_nolock(_File_00);
          if (iVar2 != -1) {
            local_20 = local_20 + 1;
          }
        }
        else if ((param_1 == 0) && ((_File_00->_flag & 2U) != 0)) {
          iVar2 = __fflush_nolock(_File_00);
          if (iVar2 == -1) {
            local_28 = -1;
          }
        }
      }
      FUN_3b408178();
    }
  }
  FUN_3b4081a7();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_3b408178(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_3b41821c + unaff_ESI * 4));
  return;
}



void FUN_3b4081a7(void)

{
  FUN_3b40aa8c(1);
  return;
}



void __cdecl FUN_3b4081b9(undefined4 param_1)

{
  DAT_3b417abc = param_1;
  return;
}



// Library Function - Single Match
//  __call_reportfault
// 
// Library: Visual Studio 2010 Release

void __cdecl __call_reportfault(int nDbgHookCode,DWORD dwExceptionCode,DWORD dwExceptionFlags)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  _EXCEPTION_POINTERS local_32c;
  EXCEPTION_RECORD local_324;
  undefined4 local_2d4;
  
  uVar1 = securityCookie ^ (uint)&stack0xfffffffc;
  if (nDbgHookCode != -1) {
    FUN_3b40de02();
  }
  local_324.ExceptionCode = 0;
  _memset(&local_324.ExceptionFlags,0,0x4c);
  local_32c.ExceptionRecord = &local_324;
  local_32c.ContextRecord = (PCONTEXT)&local_2d4;
  local_2d4 = 0x10001;
  local_324.ExceptionCode = dwExceptionCode;
  local_324.ExceptionFlags = dwExceptionFlags;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_32c);
  if (((LVar3 == 0) && (BVar2 == 0)) && (nDbgHookCode != -1)) {
    FUN_3b40de02();
  }
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2010 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  HANDLE hProcess;
  UINT uExitCode;
  
  __call_reportfault(2,0xc0000417,1);
  uExitCode = 0xc0000417;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Single Match
//  __invalid_parameter
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void __invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                        uintptr_t param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417abc);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x3b40832c. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



void FUN_3b408343(void)

{
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  unsigned long __cdecl strtoxl(struct localeinfo_struct *,char const *,char const * *,int,int)
// 
// Library: Visual Studio 2010 Release

ulong __cdecl
strtoxl(localeinfo_struct *param_1,char *param_2,char **param_3,int param_4,int param_5)

{
  ushort uVar1;
  byte *pbVar2;
  int *piVar3;
  uint uVar4;
  pthreadlocinfo ptVar5;
  uint uVar6;
  int iVar7;
  byte bVar8;
  byte *pbVar9;
  localeinfo_struct local_20;
  int local_18;
  char local_14;
  uint local_c;
  ulong local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_20,param_1);
  if (param_3 != (char **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (char *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_3b408343();
    if (local_14 != '\0') {
      *(uint *)(local_18 + 0x70) = *(uint *)(local_18 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  local_8 = 0;
  bVar8 = *param_2;
  ptVar5 = local_20.locinfo;
  pbVar2 = (byte *)param_2;
  while( true ) {
    pbVar9 = pbVar2 + 1;
    if ((int)ptVar5->locale_name[3] < 2) {
      uVar4 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2) & 8;
    }
    else {
      uVar4 = __isctype_l((uint)bVar8,8,&local_20);
      ptVar5 = local_20.locinfo;
    }
    if (uVar4 == 0) break;
    bVar8 = *pbVar9;
    pbVar2 = pbVar9;
  }
  if (bVar8 == 0x2d) {
    param_5 = param_5 | 2;
LAB_3b408404:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_3b408404;
  if (((param_4 < 0) || (param_4 == 1)) || (0x24 < param_4)) {
    if (param_3 != (char **)0x0) {
      *param_3 = param_2;
    }
    if (local_14 != '\0') {
      *(uint *)(local_18 + 0x70) = *(uint *)(local_18 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  if (param_4 == 0) {
    if (bVar8 != 0x30) {
      param_4 = 10;
      goto LAB_3b40846c;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_3b40846c;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_3b40846c;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_3b40846c:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  local_c = (uint)(0xffffffff % (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_3b4084cb:
        pbVar9 = pbVar9 + -1;
        if ((param_5 & 8U) == 0) {
          if (param_3 != (char **)0x0) {
            pbVar9 = (byte *)param_2;
          }
          local_8 = 0;
        }
        else if (((param_5 & 4U) != 0) ||
                (((param_5 & 1U) == 0 &&
                 ((((param_5 & 2U) != 0 && (0x80000000 < local_8)) ||
                  (((param_5 & 2U) == 0 && (0x7fffffff < local_8)))))))) {
          piVar3 = __errno();
          *piVar3 = 0x22;
          if ((param_5 & 1U) == 0) {
            local_8 = ((param_5 & 2U) != 0) + 0x7fffffff;
          }
          else {
            local_8 = 0xffffffff;
          }
        }
        if (param_3 != (char **)0x0) {
          *param_3 = (char *)pbVar9;
        }
        if ((param_5 & 2U) != 0) {
          local_8 = -local_8;
        }
        if (local_14 == '\0') {
          return local_8;
        }
        *(uint *)(local_18 + 0x70) = *(uint *)(local_18 + 0x70) & 0xfffffffd;
        return local_8;
      }
      iVar7 = (int)(char)bVar8;
      if ((byte)(bVar8 + 0x9f) < 0x1a) {
        iVar7 = iVar7 + -0x20;
      }
      uVar6 = iVar7 - 0x37;
    }
    else {
      uVar6 = (int)(char)bVar8 - 0x30;
    }
    if ((uint)param_4 <= uVar6) goto LAB_3b4084cb;
    if ((local_8 < uVar4) || ((local_8 == uVar4 && (uVar6 <= local_c)))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_3b4084cb;
    }
    bVar8 = *pbVar9;
    pbVar9 = pbVar9 + 1;
  } while( true );
}



// Library Function - Single Match
//  _strtol
// 
// Library: Visual Studio 2010 Release

long __cdecl _strtol(char *_Str,char **_EndPtr,int _Radix)

{
  ulong uVar1;
  undefined **ppuVar2;
  
  if (DAT_3b417adc == 0) {
    ppuVar2 = &PTR_DAT_3b416d7c;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = strtoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
}



// Library Function - Single Match
//  __filbuf
// 
// Library: Visual Studio 2010 Release

int __cdecl __filbuf(FILE *_File)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  char *_DstBuf;
  
  if (_File == (FILE *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_3b408343();
  }
  else {
    uVar4 = _File->_flag;
    if (((uVar4 & 0x83) != 0) && ((uVar4 & 0x40) == 0)) {
      if ((uVar4 & 2) == 0) {
        _File->_flag = uVar4 | 1;
        if ((uVar4 & 0x10c) == 0) {
          __getbuf(_File);
        }
        else {
          _File->_ptr = _File->_base;
        }
        uVar4 = _File->_bufsiz;
        _DstBuf = _File->_base;
        iVar3 = __fileno(_File);
        iVar3 = __read(iVar3,_DstBuf,uVar4);
        _File->_cnt = iVar3;
        if ((iVar3 != 0) && (iVar3 != -1)) {
          if ((*(byte *)&_File->_flag & 0x82) == 0) {
            iVar3 = __fileno(_File);
            if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
              puVar5 = &DAT_3b4165d0;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_3b418100)[iVar3 >> 5]);
            }
            if ((puVar5[4] & 0x82) == 0x82) {
              _File->_flag = _File->_flag | 0x2000;
            }
          }
          if (((_File->_bufsiz == 0x200) && ((_File->_flag & 8U) != 0)) &&
             ((_File->_flag & 0x400U) == 0)) {
            _File->_bufsiz = 0x1000;
          }
          _File->_cnt = _File->_cnt + -1;
          bVar1 = *_File->_ptr;
          _File->_ptr = _File->_ptr + 1;
          return (uint)bVar1;
        }
        _File->_flag = _File->_flag | (-(uint)(iVar3 != 0) & 0x10) + 0x10;
        _File->_cnt = 0;
      }
      else {
        _File->_flag = uVar4 | 0x20;
      }
    }
  }
  return -1;
}



// Library Function - Single Match
//  __ioinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __ioinit(void)

{
  void *pvVar1;
  int iVar2;
  DWORD DVar3;
  BOOL BVar4;
  HANDLE pvVar5;
  UINT UVar6;
  UINT UVar7;
  HANDLE *ppvVar8;
  void **ppvVar9;
  uint uVar10;
  _STARTUPINFOW local_50;
  HANDLE *local_c;
  UINT *local_8;
  
  GetStartupInfoW(&local_50);
  pvVar1 = __calloc_crt(0x20,0x40);
  if (pvVar1 == (void *)0x0) {
    iVar2 = -1;
  }
  else {
    uNumber_3b4180ec = 0x20;
    DAT_3b418100 = pvVar1;
    if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
      iVar2 = (int)pvVar1 + 5;
      do {
        *(undefined4 *)(iVar2 + -5) = 0xffffffff;
        *(undefined2 *)(iVar2 + -1) = 0xa00;
        *(undefined4 *)(iVar2 + 3) = 0;
        *(undefined2 *)(iVar2 + 0x1f) = 0xa00;
        *(undefined *)(iVar2 + 0x21) = 10;
        *(undefined4 *)(iVar2 + 0x33) = 0;
        *(undefined *)(iVar2 + 0x2f) = 0;
        uVar10 = iVar2 + 0x3b;
        iVar2 = iVar2 + 0x40;
      } while (uVar10 < (int)DAT_3b418100 + 0x800U);
    }
    if ((local_50.cbReserved2 != 0) && ((UINT *)local_50.lpReserved2 != (UINT *)0x0)) {
      UVar6 = *(UINT *)local_50.lpReserved2;
      local_8 = (UINT *)((int)local_50.lpReserved2 + 4);
      local_c = (HANDLE *)((int)local_8 + UVar6);
      if (0x7ff < (int)UVar6) {
        UVar6 = 0x800;
      }
      UVar7 = UVar6;
      if ((int)uNumber_3b4180ec < (int)UVar6) {
        ppvVar9 = (void **)&DAT_3b418104;
        do {
          pvVar1 = __calloc_crt(0x20,0x40);
          UVar7 = uNumber_3b4180ec;
          if (pvVar1 == (void *)0x0) break;
          uNumber_3b4180ec = uNumber_3b4180ec + 0x20;
          *ppvVar9 = pvVar1;
          if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
            iVar2 = (int)pvVar1 + 5;
            do {
              *(undefined4 *)(iVar2 + -5) = 0xffffffff;
              *(undefined4 *)(iVar2 + 3) = 0;
              *(byte *)(iVar2 + 0x1f) = *(byte *)(iVar2 + 0x1f) & 0x80;
              *(undefined4 *)(iVar2 + 0x33) = 0;
              *(undefined2 *)(iVar2 + -1) = 0xa00;
              *(undefined2 *)(iVar2 + 0x20) = 0xa0a;
              *(undefined *)(iVar2 + 0x2f) = 0;
              uVar10 = iVar2 + 0x3b;
              iVar2 = iVar2 + 0x40;
            } while (uVar10 < (int)*ppvVar9 + 0x800U);
          }
          ppvVar9 = ppvVar9 + 1;
          UVar7 = UVar6;
        } while ((int)uNumber_3b4180ec < (int)UVar6);
      }
      uVar10 = 0;
      if (0 < (int)UVar7) {
        do {
          pvVar5 = *local_c;
          if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)local_8 & 1) != 0)) &&
             (((*(byte *)local_8 & 8) != 0 || (DVar3 = GetFileType(pvVar5), DVar3 != 0)))) {
            ppvVar8 = (HANDLE *)((uVar10 & 0x1f) * 0x40 + (int)(&DAT_3b418100)[(int)uVar10 >> 5]);
            *ppvVar8 = *local_c;
            *(byte *)(ppvVar8 + 1) = *(byte *)local_8;
            BVar4 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) {
              return -1;
            }
            ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
          }
          local_c = local_c + 1;
          uVar10 = uVar10 + 1;
          local_8 = (UINT *)((int)local_8 + 1);
        } while ((int)uVar10 < (int)UVar7);
      }
    }
    iVar2 = 0;
    do {
      ppvVar8 = (HANDLE *)(iVar2 * 0x40 + (int)DAT_3b418100);
      if ((*ppvVar8 == (HANDLE)0xffffffff) || (*ppvVar8 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar8 + 1) = 0x81;
        if (iVar2 == 0) {
          DVar3 = 0xfffffff6;
        }
        else {
          DVar3 = 0xfffffff5 - (iVar2 != 1);
        }
        pvVar5 = GetStdHandle(DVar3);
        if (((pvVar5 == (HANDLE)0xffffffff) || (pvVar5 == (HANDLE)0x0)) ||
           (DVar3 = GetFileType(pvVar5), DVar3 == 0)) {
          *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          *ppvVar8 = (HANDLE)0xfffffffe;
        }
        else {
          *ppvVar8 = pvVar5;
          if ((DVar3 & 0xff) == 2) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          }
          else if ((DVar3 & 0xff) == 3) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 8;
          }
          BVar4 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
          if (BVar4 == 0) {
            return -1;
          }
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 3);
    SetHandleCount(uNumber_3b4180ec);
    iVar2 = 0;
  }
  return iVar2;
}



// Library Function - Single Match
//  __ioterm
// 
// Library: Visual Studio 2010 Release

void __cdecl __ioterm(void)

{
  void *pvVar1;
  LPCRITICAL_SECTION p_Var2;
  LPCRITICAL_SECTION lpCriticalSection;
  void **ppvVar3;
  
  ppvVar3 = (void **)&DAT_3b418100;
  do {
    pvVar1 = *ppvVar3;
    if (pvVar1 != (void *)0x0) {
      if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
        lpCriticalSection = (LPCRITICAL_SECTION)((int)pvVar1 + 0xc);
        do {
          if (lpCriticalSection[-1].SpinCount != 0) {
            DeleteCriticalSection(lpCriticalSection);
          }
          p_Var2 = lpCriticalSection + 2;
          lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[2].LockSemaphore;
        } while (&p_Var2->LockCount < (undefined *)((int)*ppvVar3 + 0x800U));
      }
      _free(*ppvVar3);
      *ppvVar3 = (void *)0x0;
    }
    ppvVar3 = ppvVar3 + 1;
  } while ((int)ppvVar3 < 0x3b418200);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __openfile
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl __openfile(char *_Filename,char *_Mode,int _ShFlag,FILE *_File)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  uchar uVar5;
  int *piVar6;
  int iVar7;
  errno_t eVar8;
  uint _OpenFlag;
  char *pcVar9;
  uchar *puVar10;
  uchar *puVar11;
  int local_c;
  uint local_8;
  
  _OpenFlag = 0;
  bVar3 = false;
  local_c = 0;
  bVar4 = false;
  for (pcVar9 = _Mode; *pcVar9 == ' '; pcVar9 = pcVar9 + 1) {
  }
  cVar1 = *pcVar9;
  if (cVar1 == 'a') {
    _OpenFlag = 0x109;
LAB_3b4089c2:
    local_8 = DAT_3b4180d0 | 2;
  }
  else {
    if (cVar1 != 'r') {
      if (cVar1 != 'w') {
        piVar6 = __errno();
        *piVar6 = 0x16;
        FUN_3b408343();
        return (FILE *)0x0;
      }
      _OpenFlag = 0x301;
      goto LAB_3b4089c2;
    }
    local_8 = DAT_3b4180d0 | 1;
  }
  bVar2 = true;
  puVar10 = (uchar *)(pcVar9 + 1);
  uVar5 = *puVar10;
  if (uVar5 != '\0') {
    do {
      if (!bVar2) break;
      iVar7 = (int)(char)uVar5;
      if (iVar7 < 0x54) {
        if (iVar7 == 0x53) {
          if (local_c != 0) goto LAB_3b408aec;
          local_c = 1;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (iVar7 != 0x20) {
          if (iVar7 == 0x2b) {
            if ((_OpenFlag & 2) != 0) goto LAB_3b408aec;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (iVar7 == 0x2c) {
            bVar4 = true;
LAB_3b408aec:
            bVar2 = false;
          }
          else if (iVar7 == 0x44) {
            if ((_OpenFlag & 0x40) != 0) goto LAB_3b408aec;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (iVar7 == 0x4e) {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (iVar7 != 0x52) goto LAB_3b408ba1;
            if (local_c != iVar7 + -0x52) goto LAB_3b408aec;
            local_c = 1;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (iVar7 == 0x54) {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_3b408aec;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (iVar7 == 0x62) {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_3b408aec;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (iVar7 == 99) {
        if (bVar3) goto LAB_3b408aec;
        local_8 = local_8 | 0x4000;
        bVar3 = true;
      }
      else if (iVar7 == 0x6e) {
        if (bVar3) goto LAB_3b408aec;
        local_8 = local_8 & 0xffffbfff;
        bVar3 = true;
      }
      else {
        if (iVar7 != 0x74) goto LAB_3b408ba1;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_3b408aec;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      puVar10 = puVar10 + 1;
      uVar5 = *puVar10;
    } while (uVar5 != '\0');
    if (bVar4) {
      for (; *puVar10 == ' '; puVar10 = puVar10 + 1) {
      }
      iVar7 = __mbsnbcmp("ccs",puVar10,3);
      if (iVar7 != 0) goto LAB_3b408ba1;
      for (puVar10 = puVar10 + 3; *puVar10 == ' '; puVar10 = puVar10 + 1) {
      }
      if (*puVar10 != '=') goto LAB_3b408ba1;
      do {
        puVar11 = puVar10;
        puVar10 = puVar11 + 1;
      } while (*puVar10 == ' ');
      iVar7 = __mbsnbicmp(puVar10,(uchar *)"UTF-8",5);
      if (iVar7 == 0) {
        puVar10 = puVar11 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __mbsnbicmp(puVar10,(uchar *)"UTF-16LE",8);
        if (iVar7 == 0) {
          puVar10 = puVar11 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __mbsnbicmp(puVar10,(uchar *)"UNICODE",7);
          if (iVar7 != 0) goto LAB_3b408ba1;
          puVar10 = puVar11 + 8;
          _OpenFlag = _OpenFlag | 0x10000;
        }
      }
    }
  }
  for (; *puVar10 == ' '; puVar10 = puVar10 + 1) {
  }
  if (*puVar10 == '\0') {
    eVar8 = __sopen_s((int *)&_Mode,_Filename,_OpenFlag,_ShFlag,0x180);
    if (eVar8 != 0) {
      return (FILE *)0x0;
    }
    _DAT_3b417418 = _DAT_3b417418 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_3b408ba1:
  piVar6 = __errno();
  *piVar6 = 0x16;
  FUN_3b408343();
  return (FILE *)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __getstream
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl __getstream(void)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  void *pvVar4;
  BOOL BVar5;
  int _Index;
  FILE *pFVar6;
  FILE *_File;
  
  pFVar6 = (FILE *)0x0;
  __lock(1);
  _Index = 0;
  do {
    _File = pFVar6;
    if (DAT_3b419220 <= _Index) {
LAB_3b408cf3:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_3b408d24();
      return _File;
    }
    piVar1 = (int *)(DAT_3b41821c + _Index * 4);
    if (*piVar1 == 0) {
      pvVar4 = __malloc_crt(0x38);
      *(void **)(DAT_3b41821c + _Index * 4) = pvVar4;
      if (pvVar4 != (void *)0x0) {
        BVar5 = InitializeCriticalSectionAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_3b41821c + _Index * 4) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(DAT_3b41821c + _Index * 4));
          *(undefined4 *)(DAT_3b41821c + _Index * 4) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_3b41821c + _Index * 4) + 0x20));
          _File = *(FILE **)(DAT_3b41821c + _Index * 4);
          _File->_flag = 0;
        }
      }
      goto LAB_3b408cf3;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((_Index - 3U < 0x11) && (iVar3 = __mtinitlocknum(_Index + 0x10), iVar3 == 0))
      goto LAB_3b408cf3;
      __lock_file2(_Index,*(void **)(DAT_3b41821c + _Index * 4));
      _File = *(FILE **)(DAT_3b41821c + _Index * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_3b408cf3;
      __unlock_file2(_Index,_File);
    }
    _Index = _Index + 1;
  } while( true );
}



void FUN_3b408d24(void)

{
  FUN_3b40aa8c(1);
  return;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Library: Visual Studio 2010 Release

void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  puStack_24 = &LAB_3b408dc0;
  uStack_28 = *unaff_FS_OFFSET;
  local_20 = securityCookie ^ (uint)&uStack_28;
  *unaff_FS_OFFSET = &uStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_3b40ce64();
    }
  }
  *unaff_FS_OFFSET = uStack_28;
  return;
}



void FUN_3b408e06(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x3b408e50. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind2@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_GlobalUnwind2_8(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  RtlUnwind(param_1,(PVOID)0x3b408e66,param_2,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



// Library Function - Single Match
//  __VEC_memzero
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

undefined (*) [16] __fastcall __VEC_memzero(undefined (*param_1) [16],uint param_2)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  
  pauVar2 = param_1;
  if (((uint)param_1 & 0xf) != 0) {
    uVar3 = 0x10 - ((uint)param_1 & 0xf);
    param_2 = param_2 - uVar3;
    for (uVar1 = uVar3 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      (*pauVar2)[0] = 0;
      pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
    }
    for (uVar3 = uVar3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined4 *)*pauVar2 = 0;
      pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
    }
  }
  for (uVar1 = param_2 >> 7; uVar1 != 0; uVar1 = uVar1 - 1) {
    *pauVar2 = (undefined  [16])0x0;
    pauVar2[1] = (undefined  [16])0x0;
    pauVar2[2] = (undefined  [16])0x0;
    pauVar2[3] = (undefined  [16])0x0;
    pauVar2[4] = (undefined  [16])0x0;
    pauVar2[5] = (undefined  [16])0x0;
    pauVar2[6] = (undefined  [16])0x0;
    pauVar2[7] = (undefined  [16])0x0;
    pauVar2 = pauVar2[8];
  }
  if ((param_2 & 0x7f) != 0) {
    for (uVar1 = (param_2 & 0x7f) >> 4; uVar1 != 0; uVar1 = uVar1 - 1) {
      *pauVar2 = (undefined  [16])0x0;
      pauVar2 = pauVar2[1];
    }
    if ((param_2 & 0xf) != 0) {
      for (uVar1 = (param_2 & 0xf) >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
        *(undefined4 *)*pauVar2 = 0;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
      }
      for (uVar1 = param_2 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
        (*pauVar2)[0] = 0;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
      }
    }
  }
  return param_1;
}



// Library Function - Single Match
//  int __cdecl CPtoLCID(int)
// 
// Library: Visual Studio 2010 Release

int __cdecl CPtoLCID(int param_1)

{
  int in_EAX;
  
  if (in_EAX == 0x3a4) {
    return 0x411;
  }
  if (in_EAX == 0x3a8) {
    return 0x804;
  }
  if (in_EAX == 0x3b5) {
    return 0x412;
  }
  if (in_EAX != 0x3b6) {
    return 0;
  }
  return 0x404;
}



// Library Function - Single Match
//  void __cdecl setSBCS(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2010 Release

void __cdecl setSBCS(threadmbcinfostruct *param_1)

{
  int in_EAX;
  undefined *puVar1;
  int iVar2;
  
  _memset((void *)(in_EAX + 0x1c),0,0x101);
  *(undefined4 *)(in_EAX + 4) = 0;
  *(undefined4 *)(in_EAX + 8) = 0;
  *(undefined4 *)(in_EAX + 0xc) = 0;
  *(undefined4 *)(in_EAX + 0x10) = 0;
  *(undefined4 *)(in_EAX + 0x14) = 0;
  *(undefined4 *)(in_EAX + 0x18) = 0;
  puVar1 = (undefined *)(in_EAX + 0x1c);
  iVar2 = 0x101;
  do {
    *puVar1 = puVar1[(int)&lpAddend_3b416610 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&lpAddend_3b416610 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2010 Release

void __cdecl setSBUpLow(threadmbcinfostruct *param_1)

{
  byte *pbVar1;
  char *pcVar2;
  BOOL BVar3;
  uint uVar4;
  CHAR CVar5;
  char cVar6;
  BYTE *pBVar7;
  int unaff_ESI;
  _cpinfo local_51c;
  WORD local_508 [256];
  CHAR local_308 [256];
  CHAR local_208 [256];
  CHAR local_108 [256];
  uint local_8;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_3b409155:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_3b409155;
        }
        *pcVar2 = '\0';
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  else {
    uVar4 = 0;
    do {
      local_108[uVar4] = (CHAR)uVar4;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
    local_108[0] = ' ';
    if (local_51c.LeadByte[0] != 0) {
      pBVar7 = local_51c.LeadByte + 1;
      do {
        uVar4 = (uint)local_51c.LeadByte[0];
        if (uVar4 <= *pBVar7) {
          _memset(local_108 + uVar4,0x20,(*pBVar7 - uVar4) + 1);
        }
        local_51c.LeadByte[0] = pBVar7[1];
        pBVar7 = pBVar7 + 2;
      } while (local_51c.LeadByte[0] != 0);
    }
    ___crtGetStringTypeA
              ((_locale_t)0x0,1,local_108,0x100,local_508,*(int *)(unaff_ESI + 4),
               *(BOOL *)(unaff_ESI + 0xc));
    ___crtLCMapStringA((_locale_t)0x0,*(LPCWSTR *)(unaff_ESI + 0xc),0x100,local_108,0x100,local_208,
                       0x100,*(int *)(unaff_ESI + 4),0);
    ___crtLCMapStringA((_locale_t)0x0,*(LPCWSTR *)(unaff_ESI + 0xc),0x200,local_108,0x100,local_308,
                       0x100,*(int *)(unaff_ESI + 4),0);
    uVar4 = 0;
    do {
      if ((local_508[uVar4] & 1) == 0) {
        if ((local_508[uVar4] & 2) != 0) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          CVar5 = local_308[uVar4];
          goto LAB_3b4090f8;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_3b4090f8:
        *(CHAR *)(unaff_ESI + 0x11d + uVar4) = CVar5;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetmbcinfo
// 
// Library: Visual Studio 2010 Release

pthreadmbcinfo __cdecl ___updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  LONG LVar2;
  pthreadmbcinfo lpAddend;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_3b416b30) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)lpAddend_3b416a38) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&lpAddend_3b416610)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)lpAddend_3b416a38;
      lpAddend = (pthreadmbcinfo)lpAddend_3b416a38;
      InterlockedIncrement((LONG *)lpAddend_3b416a38);
    }
    FUN_3b40920a();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_3b40920a(void)

{
  FUN_3b40aa8c(0xd);
  return;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2010 Release

int __cdecl getSystemCP(int param_1)

{
  UINT UVar1;
  int unaff_ESI;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(localeinfo_struct *)0x0);
  DAT_3b417ac0 = 0;
  if (unaff_ESI == -2) {
    DAT_3b417ac0 = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_3b417ac0 = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_3b417ac0 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_3b417ac0 = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return UVar1;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2010 Release

void __cdecl __setmbcp_nolock(undefined4 param_1,int param_2)

{
  BYTE *pBVar1;
  byte *pbVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  BOOL BVar6;
  undefined2 *puVar7;
  byte *pbVar8;
  int extraout_ECX;
  undefined2 *puVar9;
  int iVar10;
  undefined4 extraout_EDX;
  BYTE *pBVar11;
  threadmbcinfostruct *unaff_EDI;
  uint local_24;
  byte *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_3b4092cd:
    if (*(uint *)((int)&DAT_3b416a40 + uVar5) != uVar4) goto code_r0x3b4092d9;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_3b416a50 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_3b416a3c)[local_24];
          bVar3 = pbVar8[1];
        }
      }
      local_24 = local_24 + 1;
      pbVar8 = local_20 + 8;
      local_20 = pbVar8;
    } while (local_24 < 4);
    *(uint *)(param_2 + 4) = uVar4;
    *(undefined4 *)(param_2 + 8) = 1;
    iVar10 = CPtoLCID((int)unaff_EDI);
    *(int *)(param_2 + 0xc) = iVar10;
    puVar7 = (undefined2 *)(param_2 + 0x10);
    puVar9 = (undefined2 *)(&DAT_3b416a44 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_3b409401;
  }
LAB_3b4092ba:
  setSBCS(unaff_EDI);
LAB_3b409469:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x3b4092d9:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x3b4092e6;
  goto LAB_3b4092cd;
code_r0x3b4092e6:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_3b409469;
  BVar6 = GetCPInfo(uVar4,&local_1c);
  if (BVar6 != 0) {
    _memset((void *)(param_2 + 0x1c),0,0x101);
    *(uint *)(param_2 + 4) = uVar4;
    *(undefined4 *)(param_2 + 0xc) = 0;
    if (local_1c.MaxCharSize < 2) {
      *(undefined4 *)(param_2 + 8) = 0;
    }
    else {
      if (local_1c.LeadByte[0] != '\0') {
        pBVar11 = local_1c.LeadByte + 1;
        do {
          bVar3 = *pBVar11;
          if (bVar3 == 0) break;
          for (uVar4 = (uint)pBVar11[-1]; uVar4 <= bVar3; uVar4 = uVar4 + 1) {
            pbVar8 = (byte *)(param_2 + 0x1d + uVar4);
            *pbVar8 = *pbVar8 | 4;
          }
          pBVar1 = pBVar11 + 1;
          pBVar11 = pBVar11 + 2;
        } while (*pBVar1 != 0);
      }
      pbVar8 = (byte *)(param_2 + 0x1e);
      iVar10 = 0xfe;
      do {
        *pbVar8 = *pbVar8 | 8;
        pbVar8 = pbVar8 + 1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
      iVar10 = CPtoLCID((int)unaff_EDI);
      *(int *)(param_2 + 0xc) = iVar10;
      *(undefined4 *)(param_2 + 8) = extraout_EDX;
    }
    *(undefined4 *)(param_2 + 0x10) = 0;
    *(undefined4 *)(param_2 + 0x14) = 0;
    *(undefined4 *)(param_2 + 0x18) = 0;
LAB_3b409401:
    setSBUpLow(unaff_EDI);
    goto LAB_3b409469;
  }
  if (DAT_3b417ac0 == 0) goto LAB_3b409469;
  goto LAB_3b4092ba;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setmbcp
// 
// Library: Visual Studio 2010 Release

int __cdecl __setmbcp(int _CodePage)

{
  _ptiddata p_Var1;
  int iVar2;
  pthreadmbcinfo ptVar3;
  LONG LVar4;
  int *piVar5;
  int iVar6;
  pthreadmbcinfo ptVar7;
  pthreadmbcinfo ptVar8;
  int in_stack_ffffffc8;
  int local_24;
  
  local_24 = -1;
  p_Var1 = __getptd();
  ___updatetmbcinfo();
  ptVar3 = p_Var1->ptmbcinfo;
  iVar2 = getSystemCP(in_stack_ffffffc8);
  if (iVar2 == ptVar3->mbcodepage) {
    local_24 = 0;
  }
  else {
    ptVar3 = (pthreadmbcinfo)__malloc_crt(0x220);
    if (ptVar3 != (pthreadmbcinfo)0x0) {
      ptVar7 = p_Var1->ptmbcinfo;
      ptVar8 = ptVar3;
      for (iVar6 = 0x88; iVar6 != 0; iVar6 = iVar6 + -1) {
        ptVar8->refcount = (int)ptVar7->refcount;
        ptVar7 = (pthreadmbcinfo)&ptVar7->mbcodepage;
        ptVar8 = (pthreadmbcinfo)&ptVar8->mbcodepage;
      }
      ptVar3->refcount = 0;
      local_24 = __setmbcp_nolock(iVar2,(int)ptVar3);
      if (local_24 == 0) {
        LVar4 = InterlockedDecrement(&p_Var1->ptmbcinfo->refcount);
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&lpAddend_3b416610)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_3b416b30 & 1) == 0)) {
          __lock(0xd);
          _DAT_3b417ad0 = ptVar3->mbcodepage;
          _DAT_3b417ad4 = ptVar3->ismbcodepage;
          _DAT_3b417ad8 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_3b417ac4)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_3b416830)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_3b416938)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)lpAddend_3b416a38);
          if ((LVar4 == 0) && ((LONG **)lpAddend_3b416a38 != &lpAddend_3b416610)) {
            _free(lpAddend_3b416a38);
          }
          lpAddend_3b416a38 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_3b4095d9();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&lpAddend_3b416610) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_3b4095d9(void)

{
  FUN_3b40aa8c(0xd);
  return;
}



// Library Function - Single Match
//  ___initmbctable
// 
// Library: Visual Studio 2010 Release

undefined4 ___initmbctable(void)

{
  if (DAT_3b41820c == 0) {
    __setmbcp(-3);
    DAT_3b41820c = 1;
  }
  return 0;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Library: Visual Studio 2010 Release

void __cdecl ___addlocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  InterlockedIncrement(param_1);
  if ((LONG *)param_1[0x2c] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2c]);
  }
  if ((LONG *)param_1[0x2e] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2e]);
  }
  if ((LONG *)param_1[0x2d] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2d]);
  }
  if ((LONG *)param_1[0x30] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x30]);
  }
  ppLVar2 = (LONG **)(param_1 + 0x14);
  param_1 = (LONG *)0x6;
  do {
    if ((ppLVar2[-2] != (LONG *)&DAT_3b416b34) && (*ppLVar2 != (LONG *)0x0)) {
      InterlockedIncrement(*ppLVar2);
    }
    if ((ppLVar2[-1] != (LONG *)0x0) && (ppLVar2[1] != (LONG *)0x0)) {
      InterlockedIncrement(ppLVar2[1]);
    }
    ppLVar2 = ppLVar2 + 4;
    param_1 = (LONG *)((int)param_1 + -1);
  } while (param_1 != (LONG *)0x0);
  InterlockedIncrement((LONG *)(pLVar1[0x35] + 0xb4));
  return;
}



// Library Function - Single Match
//  ___removelocaleref
// 
// Library: Visual Studio 2010 Release

LONG * __cdecl ___removelocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  if (param_1 != (LONG *)0x0) {
    InterlockedDecrement(param_1);
    if ((LONG *)param_1[0x2c] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2c]);
    }
    if ((LONG *)param_1[0x2e] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2e]);
    }
    if ((LONG *)param_1[0x2d] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2d]);
    }
    if ((LONG *)param_1[0x30] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x30]);
    }
    ppLVar2 = (LONG **)(param_1 + 0x14);
    param_1 = (LONG *)0x6;
    do {
      if ((ppLVar2[-2] != (LONG *)&DAT_3b416b34) && (*ppLVar2 != (LONG *)0x0)) {
        InterlockedDecrement(*ppLVar2);
      }
      if ((ppLVar2[-1] != (LONG *)0x0) && (ppLVar2[1] != (LONG *)0x0)) {
        InterlockedDecrement(ppLVar2[1]);
      }
      ppLVar2 = ppLVar2 + 4;
      param_1 = (LONG *)((int)param_1 + -1);
    } while (param_1 != (LONG *)0x0);
    InterlockedDecrement((LONG *)(pLVar1[0x35] + 0xb4));
  }
  return pLVar1;
}



// Library Function - Single Match
//  ___freetlocinfo
// 
// Library: Visual Studio 2010 Release

void __cdecl ___freetlocinfo(void *param_1)

{
  int *piVar1;
  undefined **ppuVar2;
  void *_Memory;
  int **ppiVar3;
  
  _Memory = param_1;
  if ((((*(undefined ***)((int)param_1 + 0xbc) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_3b416ff8)) &&
      (*(int **)((int)param_1 + 0xb0) != (int *)0x0)) && (**(int **)((int)param_1 + 0xb0) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0xb8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free(piVar1);
      ___free_lconv_mon(*(int *)((int)param_1 + 0xbc));
    }
    piVar1 = *(int **)((int)param_1 + 0xb4);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free(piVar1);
      ___free_lconv_num(*(void ***)((int)param_1 + 0xbc));
    }
    _free(*(void **)((int)param_1 + 0xb0));
    _free(*(void **)((int)param_1 + 0xbc));
  }
  if ((*(int **)((int)param_1 + 0xc0) != (int *)0x0) && (**(int **)((int)param_1 + 0xc0) == 0)) {
    _free((void *)(*(int *)((int)param_1 + 0xc4) + -0xfe));
    _free((void *)(*(int *)((int)param_1 + 0xcc) + -0x80));
    _free((void *)(*(int *)((int)param_1 + 0xd0) + -0x80));
    _free(*(void **)((int)param_1 + 0xc0));
  }
  ppuVar2 = *(undefined ***)((int)param_1 + 0xd4);
  if ((ppuVar2 != &PTR_DAT_3b416b38) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_3b416b34) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    if (((ppiVar3[-1] != (int *)0x0) && (piVar1 = ppiVar3[1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    ppiVar3 = ppiVar3 + 4;
    param_1 = (void *)((int)param_1 + -1);
  } while (param_1 != (void *)0x0);
  _free(_Memory);
  return;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2010 Release

LONG * __cdecl __updatetlocinfoEx_nolock(LONG **param_1,LONG *param_2)

{
  LONG *pLVar1;
  
  if ((param_2 == (LONG *)0x0) || (param_1 == (LONG **)0x0)) {
    param_2 = (LONG *)0x0;
  }
  else {
    pLVar1 = *param_1;
    if (pLVar1 != param_2) {
      *param_1 = param_2;
      ___addlocaleref(param_2);
      if (((pLVar1 != (LONG *)0x0) && (___removelocaleref(pLVar1), *pLVar1 == 0)) &&
         (pLVar1 != (LONG *)&DAT_3b416ca0)) {
        ___freetlocinfo(pLVar1);
      }
    }
  }
  return param_2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetlocinfo
// 
// Library: Visual Studio 2010 Release

pthreadlocinfo __cdecl ___updatetlocinfo(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar2;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_3b416b30) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    ptVar2 = (pthreadlocinfo)&p_Var1->ptlocinfo;
    __updatetlocinfoEx_nolock((LONG **)ptVar2,(LONG *)PTR_DAT_3b416d78);
    FUN_3b40995d();
  }
  else {
    p_Var1 = __getptd();
    ptVar2 = p_Var1->ptlocinfo;
  }
  if (ptVar2 == (pthreadlocinfo)0x0) {
    __amsg_exit(0x20);
  }
  return ptVar2;
}



void FUN_3b40995d(void)

{
  FUN_3b40aa8c(0xc);
  return;
}



// Library Function - Single Match
//  __tolower_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __tolower_l(int _C,_locale_t _Locale)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  CHAR CVar5;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  CHAR local_8;
  CHAR local_7;
  undefined local_6;
  
  iVar1 = _C;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if ((uint)_C < 0x100) {
    if ((int)(local_1c.locinfo)->locale_name[3] < 2) {
      uVar2 = *(ushort *)(local_1c.locinfo[1].lc_category[0].locale + _C * 2) & 1;
    }
    else {
      uVar2 = __isctype_l(_C,1,&local_1c);
    }
    if (uVar2 == 0) {
LAB_3b4099ca:
      if (local_10 == '\0') {
        return iVar1;
      }
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      return iVar1;
    }
    uVar2 = (uint)*(byte *)((int)local_1c.locinfo[1].lc_category[0].wlocale + _C);
  }
  else {
    CVar5 = (CHAR)_C;
    if (((int)(local_1c.locinfo)->locale_name[3] < 2) ||
       (iVar3 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c), iVar3 == 0)) {
      piVar4 = __errno();
      *piVar4 = 0x2a;
      local_7 = '\0';
      iVar3 = 1;
      local_8 = CVar5;
    }
    else {
      _C._0_1_ = (CHAR)((uint)_C >> 8);
      local_8 = (CHAR)_C;
      local_6 = 0;
      iVar3 = 2;
      local_7 = CVar5;
    }
    iVar3 = ___crtLCMapStringA(&local_1c,(local_1c.locinfo)->lc_category[0].wlocale,0x100,&local_8,
                               iVar3,(LPSTR)&local_c,3,(local_1c.locinfo)->lc_codepage,1);
    if (iVar3 == 0) goto LAB_3b4099ca;
    uVar2 = (uint)local_c;
    if (iVar3 != 1) {
      uVar2 = (uint)CONCAT11(local_c,local_b);
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return uVar2;
}



// Library Function - Single Match
//  __flsbuf
// 
// Library: Visual Studio 2010 Release

int __cdecl __flsbuf(int _Ch,FILE *_File)

{
  char *_Buf;
  char *pcVar1;
  FILE *_File_00;
  int *piVar2;
  undefined **ppuVar3;
  int iVar4;
  undefined *puVar5;
  uint uVar6;
  longlong lVar7;
  uint local_8;
  
  _File_00 = _File;
  _File = (FILE *)__fileno(_File);
  uVar6 = _File_00->_flag;
  if ((uVar6 & 0x82) == 0) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_3b409aa4:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_3b409aa4;
  }
  if ((uVar6 & 1) != 0) {
    _File_00->_cnt = 0;
    if ((uVar6 & 0x10) == 0) {
      _File_00->_flag = uVar6 | 0x20;
      return -1;
    }
    _File_00->_ptr = _File_00->_base;
    _File_00->_flag = uVar6 & 0xfffffffe;
  }
  uVar6 = _File_00->_flag;
  _File_00->_flag = uVar6 & 0xffffffef | 2;
  _File_00->_cnt = 0;
  local_8 = 0;
  if (((uVar6 & 0x10c) == 0) &&
     (((ppuVar3 = FUN_3b405a71(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_3b405a71(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
      (iVar4 = __isatty((int)_File), iVar4 == 0)))) {
    __getbuf(_File_00);
  }
  if ((_File_00->_flag & 0x108U) == 0) {
    uVar6 = 1;
    local_8 = __write((int)_File,&_Ch,1);
  }
  else {
    _Buf = _File_00->_base;
    pcVar1 = _File_00->_ptr;
    _File_00->_ptr = _Buf + 1;
    uVar6 = (int)pcVar1 - (int)_Buf;
    _File_00->_cnt = _File_00->_bufsiz + -1;
    if ((int)uVar6 < 1) {
      if ((_File == (FILE *)0xffffffff) || (_File == (FILE *)0xfffffffe)) {
        puVar5 = &DAT_3b4165d0;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_3b418100)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) && (lVar7 = __lseeki64((int)_File,0,2), lVar7 == -1))
      goto LAB_3b409bcc;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_3b409bcc:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2010 Release

void __fastcall _write_char(FILE *param_1)

{
  int *piVar1;
  byte in_AL;
  uint uVar2;
  int *unaff_ESI;
  
  if (((*(byte *)&param_1->_flag & 0x40) == 0) || (param_1->_base != (char *)0x0)) {
    piVar1 = &param_1->_cnt;
    *piVar1 = *piVar1 + -1;
    if (*piVar1 < 0) {
      uVar2 = __flsbuf((int)(char)in_AL,param_1);
    }
    else {
      *param_1->_ptr = in_AL;
      param_1->_ptr = param_1->_ptr + 1;
      uVar2 = (uint)in_AL;
    }
    if (uVar2 == 0xffffffff) {
      *unaff_ESI = -1;
      return;
    }
  }
  *unaff_ESI = *unaff_ESI + 1;
  return;
}



void __cdecl FUN_3b409c15(undefined4 param_1,int param_2)

{
  int iVar1;
  int *in_EAX;
  FILE *unaff_EBX;
  int *unaff_EDI;
  
  iVar1 = *unaff_EDI;
  if (((*(byte *)&unaff_EBX->_flag & 0x40) == 0) || (unaff_EBX->_base != (char *)0x0)) {
    *unaff_EDI = 0;
    if (0 < param_2) {
      do {
        param_2 = param_2 + -1;
        _write_char(unaff_EBX);
        if (*in_EAX == -1) {
          if (*unaff_EDI != 0x2a) break;
          _write_char(unaff_EBX);
        }
      } while (0 < param_2);
      if (*unaff_EDI != 0) {
        return;
      }
    }
    *unaff_EDI = iVar1;
  }
  else {
    *in_EAX = *in_EAX + param_2;
  }
  return;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_3b409c77(FILE *param_1,byte *param_2,localeinfo_struct *param_3,int **param_4)

{
  byte bVar1;
  wchar_t _WCh;
  int *piVar2;
  FILE *pFVar3;
  int *piVar4;
  uint uVar5;
  undefined3 extraout_var;
  code *pcVar6;
  int *piVar7;
  char *pcVar8;
  errno_t eVar9;
  undefined *puVar10;
  int extraout_ECX;
  int iVar11;
  byte *pbVar12;
  int **ppiVar13;
  bool bVar14;
  undefined8 uVar15;
  int *local_284;
  int *local_280;
  undefined4 local_27c;
  int local_278;
  int local_274;
  int *local_270;
  size_t local_26c;
  char *local_264;
  localeinfo_struct local_260;
  int local_258;
  char local_254;
  int local_250;
  int *local_24c;
  int local_248;
  byte *local_244;
  int local_240;
  int *local_23c;
  int local_238;
  FILE *local_234;
  undefined local_230;
  char local_22f;
  size_t local_22c;
  int local_228;
  int *local_224;
  int **local_220;
  int *local_21c;
  byte local_215;
  uint local_214;
  int local_210 [127];
  undefined4 local_11;
  uint local_8;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  local_234 = param_1;
  local_220 = param_4;
  local_250 = 0;
  local_214 = 0;
  local_23c = (int *)0x0;
  local_21c = (int *)0x0;
  local_238 = 0;
  local_248 = 0;
  local_240 = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_260,param_3);
  local_270 = __errno();
  if (param_1 != (FILE *)0x0) {
    if ((*(byte *)&param_1->_flag & 0x40) == 0) {
      uVar5 = __fileno(param_1);
      if ((uVar5 == 0xffffffff) || (uVar5 == 0xfffffffe)) {
        puVar10 = &DAT_3b4165d0;
      }
      else {
        puVar10 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar5 >> 5]);
      }
      if ((puVar10[0x24] & 0x7f) == 0) {
        if ((uVar5 == 0xffffffff) || (uVar5 == 0xfffffffe)) {
          puVar10 = &DAT_3b4165d0;
        }
        else {
          puVar10 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar5 >> 5]);
        }
        if ((puVar10[0x24] & 0x80) == 0) goto LAB_3b409d7c;
      }
    }
    else {
LAB_3b409d7c:
      if (param_2 != (byte *)0x0) {
        local_215 = *param_2;
        local_228 = 0;
        local_22c = 0;
        local_24c = (int *)0x0;
        iVar11 = 0;
        ppiVar13 = local_220;
        while ((local_220 = ppiVar13, local_215 != 0 &&
               (pbVar12 = param_2 + 1, local_244 = pbVar12, -1 < local_228))) {
          if ((byte)(local_215 - 0x20) < 0x59) {
            uVar5 = (int)(char)(&DAT_3b412888)[(char)local_215] & 0xf;
          }
          else {
            uVar5 = 0;
          }
          local_278 = (int)(char)(&DAT_3b4128a8)[uVar5 * 8 + iVar11] >> 4;
          switch(local_278) {
          case 0:
switchD_3b409df1_caseD_0:
            local_240 = 0;
            iVar11 = __isleadbyte_l((uint)local_215,&local_260);
            if (iVar11 != 0) {
              _write_char(local_234);
              local_244 = param_2 + 2;
              if (*pbVar12 == 0) goto LAB_3b409ced;
            }
            _write_char(local_234);
            break;
          case 1:
            local_21c = (int *)0xffffffff;
            local_27c = 0;
            local_248 = 0;
            local_23c = (int *)0x0;
            local_238 = 0;
            local_214 = 0;
            local_240 = 0;
            break;
          case 2:
            if (local_215 == 0x20) {
              local_214 = local_214 | 2;
            }
            else if (local_215 == 0x23) {
              local_214 = local_214 | 0x80;
            }
            else if (local_215 == 0x2b) {
              local_214 = local_214 | 1;
            }
            else if (local_215 == 0x2d) {
              local_214 = local_214 | 4;
            }
            else if (local_215 == 0x30) {
              local_214 = local_214 | 8;
            }
            break;
          case 3:
            if (local_215 == 0x2a) {
              local_23c = *param_4;
              local_220 = param_4 + 1;
              if ((int)local_23c < 0) {
                local_214 = local_214 | 4;
                local_23c = (int *)-(int)local_23c;
              }
            }
            else {
              local_23c = (int *)((int)local_23c * 10 + -0x30 + (int)(char)local_215);
            }
            break;
          case 4:
            local_21c = (int *)0x0;
            break;
          case 5:
            if (local_215 == 0x2a) {
              local_21c = *param_4;
              local_220 = param_4 + 1;
              if ((int)local_21c < 0) {
                local_21c = (int *)0xffffffff;
              }
            }
            else {
              local_21c = (int *)((int)local_21c * 10 + -0x30 + (int)(char)local_215);
            }
            break;
          case 6:
            if (local_215 == 0x49) {
              bVar1 = *pbVar12;
              if ((bVar1 == 0x36) && (param_2[2] == 0x34)) {
                local_214 = local_214 | 0x8000;
                local_244 = param_2 + 3;
              }
              else if ((bVar1 == 0x33) && (param_2[2] == 0x32)) {
                local_214 = local_214 & 0xffff7fff;
                local_244 = param_2 + 3;
              }
              else if (((((bVar1 != 100) && (bVar1 != 0x69)) && (bVar1 != 0x6f)) &&
                       ((bVar1 != 0x75 && (bVar1 != 0x78)))) && (bVar1 != 0x58)) {
                local_278 = 0;
                goto switchD_3b409df1_caseD_0;
              }
            }
            else if (local_215 == 0x68) {
              local_214 = local_214 | 0x20;
            }
            else if (local_215 == 0x6c) {
              if (*pbVar12 == 0x6c) {
                local_214 = local_214 | 0x1000;
                local_244 = param_2 + 2;
              }
              else {
                local_214 = local_214 | 0x10;
              }
            }
            else if (local_215 == 0x77) {
              local_214 = local_214 | 0x800;
            }
            break;
          case 7:
            if ((char)local_215 < 'e') {
              if (local_215 == 100) {
LAB_3b40a2bd:
                local_214 = local_214 | 0x40;
LAB_3b40a2c4:
                ppiVar13 = param_4;
                local_22c = 10;
LAB_3b40a2ce:
                if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
                  local_220 = ppiVar13 + 1;
                  if ((local_214 & 0x20) == 0) {
                    piVar4 = *ppiVar13;
                    if ((local_214 & 0x40) == 0) {
                      piVar7 = (int *)0x0;
                    }
                    else {
                      piVar7 = (int *)((int)piVar4 >> 0x1f);
                    }
                  }
                  else {
                    if ((local_214 & 0x40) == 0) {
                      piVar4 = (int *)(uint)*(ushort *)ppiVar13;
                    }
                    else {
                      piVar4 = (int *)(int)*(short *)ppiVar13;
                    }
                    piVar7 = (int *)((int)piVar4 >> 0x1f);
                  }
                }
                else {
                  piVar4 = *ppiVar13;
                  piVar7 = ppiVar13[1];
                  local_220 = ppiVar13 + 2;
                }
                if ((((local_214 & 0x40) != 0) && ((int)piVar7 < 1)) && ((int)piVar7 < 0)) {
                  bVar14 = piVar4 != (int *)0x0;
                  piVar4 = (int *)-(int)piVar4;
                  piVar7 = (int *)-(int)((int)piVar7 + (uint)bVar14);
                  local_214 = local_214 | 0x100;
                }
                uVar15 = CONCAT44(piVar7,piVar4);
                if ((local_214 & 0x9000) == 0) {
                  piVar7 = (int *)0x0;
                }
                if ((int)local_21c < 0) {
                  local_21c = (int *)0x1;
                }
                else {
                  local_214 = local_214 & 0xfffffff7;
                  if (0x200 < (int)local_21c) {
                    local_21c = (int *)0x200;
                  }
                }
                if (((uint)piVar4 | (uint)piVar7) == 0) {
                  local_238 = 0;
                }
                piVar4 = &local_11;
                while( true ) {
                  pcVar8 = (char *)uVar15;
                  piVar2 = (int *)((int)local_21c + -1);
                  if (((int)local_21c < 1) && (((uint)pcVar8 | (uint)piVar7) == 0)) break;
                  local_21c = piVar2;
                  uVar15 = __aulldvrm((uint)pcVar8,(uint)piVar7,local_22c,(int)local_22c >> 0x1f);
                  piVar7 = (int *)((ulonglong)uVar15 >> 0x20);
                  iVar11 = extraout_ECX + 0x30;
                  if (0x39 < iVar11) {
                    iVar11 = iVar11 + local_250;
                  }
                  *(char *)piVar4 = (char)iVar11;
                  piVar4 = (int *)((int)piVar4 + -1);
                  local_264 = pcVar8;
                }
                local_22c = (int)&local_11 + -(int)piVar4;
                local_224 = (int *)((int)piVar4 + 1);
                local_21c = piVar2;
                if (((local_214 & 0x200) != 0) && ((local_22c == 0 || (*(char *)local_224 != '0'))))
                {
                  *(char *)piVar4 = '0';
                  local_22c = (int)&local_11 + -(int)piVar4 + 1;
                  local_224 = piVar4;
                }
              }
              else if ((char)local_215 < 'T') {
                if (local_215 == 0x53) {
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
                  goto LAB_3b40a0d2;
                }
                if (local_215 == 0x41) {
LAB_3b40a085:
                  local_215 = local_215 + 0x20;
                  local_27c = 1;
LAB_3b40a2f3:
                  local_214 = local_214 | 0x40;
                  local_264 = (char *)0x200;
                  piVar7 = local_210;
                  pcVar8 = local_264;
                  piVar4 = local_210;
                  if ((int)local_21c < 0) {
                    local_21c = (int *)0x6;
                  }
                  else if (local_21c == (int *)0x0) {
                    if (local_215 == 0x67) {
                      local_21c = (int *)0x1;
                    }
                  }
                  else {
                    if (0x200 < (int)local_21c) {
                      local_21c = (int *)0x200;
                    }
                    if (0xa3 < (int)local_21c) {
                      pcVar8 = (char *)((int)local_21c + 0x15d);
                      local_224 = local_210;
                      local_24c = (int *)__malloc_crt((size_t)pcVar8);
                      piVar7 = local_24c;
                      piVar4 = local_24c;
                      if (local_24c == (int *)0x0) {
                        local_21c = (int *)0xa3;
                        piVar7 = local_210;
                        pcVar8 = local_264;
                        piVar4 = local_224;
                      }
                    }
                  }
                  local_224 = piVar4;
                  local_264 = pcVar8;
                  puVar10 = PTR_FUN_3b416004;
                  local_284 = *param_4;
                  local_220 = param_4 + 2;
                  local_280 = param_4[1];
                  pcVar6 = (code *)(*(code *)PTR_FUN_3b416004)
                                             (PTR_LAB_3b416ed8,&local_284,piVar7,local_264,
                                              (int)(char)local_215,local_21c,local_27c,&local_260);
                  (*pcVar6)();
                  uVar5 = local_214 & 0x80;
                  if ((uVar5 != 0) && (local_21c == (int *)0x0)) {
                    pcVar6 = (code *)(*(code *)puVar10)(PTR_LAB_3b416ee4,piVar7,&local_260);
                    (*pcVar6)();
                  }
                  if ((local_215 == 0x67) && (uVar5 == 0)) {
                    pcVar6 = (code *)(*(code *)puVar10)(PTR_LAB_3b416ee0,piVar7,&local_260);
                    (*pcVar6)();
                  }
                  if (*(char *)piVar7 == '-') {
                    local_214 = local_214 | 0x100;
                    local_224 = (int *)((int)piVar7 + 1);
                    piVar7 = local_224;
                  }
LAB_3b40a20a:
                  local_22c = _strlen((char *)piVar7);
                }
                else if (local_215 == 0x43) {
                  ppiVar13 = param_4;
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
LAB_3b40a14b:
                  local_220 = ppiVar13 + 1;
                  if ((local_214 & 0x810) == 0) {
                    local_210[0]._0_1_ = *(char *)ppiVar13;
                    local_22c = 1;
                  }
                  else {
                    eVar9 = _wctomb_s((int *)&local_22c,(char *)local_210,0x200,*(wchar_t *)ppiVar13
                                     );
                    if (eVar9 != 0) {
                      local_248 = 1;
                    }
                  }
                  local_224 = local_210;
                }
                else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_3b40a085;
              }
              else {
                if (local_215 == 0x58) goto LAB_3b40a453;
                if (local_215 == 0x5a) {
                  piVar4 = *param_4;
                  local_220 = param_4 + 1;
                  piVar7 = (int *)PTR_s__null__3b416d88;
                  local_224 = (int *)PTR_s__null__3b416d88;
                  if ((piVar4 == (int *)0x0) || (piVar2 = (int *)piVar4[1], piVar2 == (int *)0x0))
                  goto LAB_3b40a20a;
                  local_22c = (size_t)*(wchar_t *)piVar4;
                  local_224 = piVar2;
                  if ((local_214 & 0x800) == 0) {
                    local_240 = 0;
                  }
                  else {
                    local_22c = (int)local_22c / 2;
                    local_240 = 1;
                  }
                }
                else {
                  if (local_215 == 0x61) goto LAB_3b40a2f3;
                  if (local_215 == 99) goto LAB_3b40a14b;
                }
              }
LAB_3b40a630:
              if (local_248 == 0) {
                if ((local_214 & 0x40) != 0) {
                  if ((local_214 & 0x100) == 0) {
                    if ((local_214 & 1) == 0) {
                      if ((local_214 & 2) == 0) goto LAB_3b40a67d;
                      local_230 = 0x20;
                    }
                    else {
                      local_230 = 0x2b;
                    }
                  }
                  else {
                    local_230 = 0x2d;
                  }
                  local_238 = 1;
                }
LAB_3b40a67d:
                pcVar8 = (char *)((int)local_23c + (-local_238 - local_22c));
                local_264 = pcVar8;
                if ((local_214 & 0xc) == 0) {
                  do {
                    if ((int)pcVar8 < 1) break;
                    pcVar8 = pcVar8 + -1;
                    _write_char(local_234);
                  } while (local_228 != -1);
                }
                pFVar3 = local_234;
                FUN_3b409c15(&local_230,local_238);
                if (((local_214 & 8) != 0) && (pcVar8 = local_264, (local_214 & 4) == 0)) {
                  do {
                    if ((int)pcVar8 < 1) break;
                    _write_char(pFVar3);
                    pcVar8 = pcVar8 + -1;
                  } while (local_228 != -1);
                }
                if ((local_240 == 0) || ((int)local_22c < 1)) {
                  FUN_3b409c15(local_224,local_22c);
                }
                else {
                  local_26c = local_22c;
                  piVar4 = local_224;
                  do {
                    _WCh = *(wchar_t *)piVar4;
                    local_26c = local_26c - 1;
                    piVar4 = (int *)((int)piVar4 + 2);
                    eVar9 = _wctomb_s(&local_274,(char *)((int)&local_11 + 1),6,_WCh);
                    if ((eVar9 != 0) || (local_274 == 0)) {
                      local_228 = -1;
                      break;
                    }
                    FUN_3b409c15((int)&local_11 + 1,local_274);
                  } while (local_26c != 0);
                }
                if ((-1 < local_228) && (pcVar8 = local_264, (local_214 & 4) != 0)) {
                  do {
                    if ((int)pcVar8 < 1) break;
                    _write_char(local_234);
                    pcVar8 = pcVar8 + -1;
                  } while (local_228 != -1);
                }
              }
            }
            else {
              if ('p' < (char)local_215) {
                if (local_215 == 0x73) {
LAB_3b40a0d2:
                  piVar4 = local_21c;
                  if (local_21c == (int *)0xffffffff) {
                    piVar4 = (int *)0x7fffffff;
                  }
                  local_220 = param_4 + 1;
                  local_224 = *param_4;
                  if ((local_214 & 0x810) == 0) {
                    piVar7 = local_224;
                    if (local_224 == (int *)0x0) {
                      piVar7 = (int *)PTR_s__null__3b416d88;
                      local_224 = (int *)PTR_s__null__3b416d88;
                    }
                    for (; (piVar4 != (int *)0x0 &&
                           (piVar4 = (int *)((int)piVar4 + -1), *(char *)piVar7 != '\0'));
                        piVar7 = (int *)((int)piVar7 + 1)) {
                    }
                    local_22c = (int)piVar7 - (int)local_224;
                  }
                  else {
                    if (local_224 == (int *)0x0) {
                      local_224 = (int *)PTR_u__null__3b416d8c;
                    }
                    local_240 = 1;
                    for (piVar7 = local_224;
                        (piVar4 != (int *)0x0 &&
                        (piVar4 = (int *)((int)piVar4 + -1), *(wchar_t *)piVar7 != L'\0'));
                        piVar7 = (int *)((int)piVar7 + 2)) {
                    }
                    local_22c = (int)piVar7 - (int)local_224 >> 1;
                  }
                  goto LAB_3b40a630;
                }
                if (local_215 == 0x75) goto LAB_3b40a2c4;
                if (local_215 != 0x78) goto LAB_3b40a630;
                local_250 = 0x27;
LAB_3b40a485:
                local_22c = 0x10;
                if ((local_214 & 0x80) != 0) {
                  local_22f = (char)local_250 + 'Q';
                  local_230 = 0x30;
                  local_238 = 2;
                }
                goto LAB_3b40a2ce;
              }
              if (local_215 == 0x70) {
                local_21c = (int *)0x8;
LAB_3b40a453:
                local_250 = 7;
                ppiVar13 = param_4;
                goto LAB_3b40a485;
              }
              if ((char)local_215 < 'e') goto LAB_3b40a630;
              param_4 = ppiVar13;
              if ((char)local_215 < 'h') goto LAB_3b40a2f3;
              if (local_215 == 0x69) goto LAB_3b40a2bd;
              if (local_215 != 0x6e) {
                if (local_215 != 0x6f) goto LAB_3b40a630;
                local_22c = 8;
                if ((local_214 & 0x80) != 0) {
                  local_214 = local_214 | 0x200;
                }
                goto LAB_3b40a2ce;
              }
              local_220 = ppiVar13 + 1;
              piVar4 = *ppiVar13;
              bVar14 = FUN_3b410145();
              if (CONCAT31(extraout_var,bVar14) == 0) goto LAB_3b409ced;
              if ((local_214 & 0x20) == 0) {
                *piVar4 = local_228;
              }
              else {
                *(wchar_t *)piVar4 = (wchar_t)local_228;
              }
              local_248 = 1;
            }
            if (local_24c != (int *)0x0) {
              _free(local_24c);
              local_24c = (int *)0x0;
            }
          }
          local_215 = *local_244;
          iVar11 = local_278;
          param_2 = local_244;
          param_4 = local_220;
          ppiVar13 = local_220;
        }
        if (local_254 != '\0') {
          *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
        }
        goto LAB_3b40a84f;
      }
    }
  }
LAB_3b409ced:
  piVar4 = __errno();
  *piVar4 = 0x16;
  FUN_3b408343();
  if (local_254 != '\0') {
    *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
  }
LAB_3b40a84f:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __stbuf
// 
// Library: Visual Studio 2010 Release

int __cdecl __stbuf(FILE *_File)

{
  char **ppcVar1;
  int iVar2;
  undefined **ppuVar3;
  char *pcVar4;
  
  iVar2 = __fileno(_File);
  iVar2 = __isatty(iVar2);
  if (iVar2 == 0) {
    return 0;
  }
  ppuVar3 = FUN_3b405a71();
  if (_File == (FILE *)(ppuVar3 + 8)) {
    iVar2 = 0;
  }
  else {
    ppuVar3 = FUN_3b405a71();
    if (_File != (FILE *)(ppuVar3 + 0x10)) {
      return 0;
    }
    iVar2 = 1;
  }
  _DAT_3b417418 = _DAT_3b417418 + 1;
  if ((_File->_flag & 0x10cU) != 0) {
    return 0;
  }
  ppcVar1 = (char **)(&DAT_3b417ae0 + iVar2);
  if (*ppcVar1 == (char *)0x0) {
    pcVar4 = (char *)__malloc_crt(0x1000);
    *ppcVar1 = pcVar4;
    if (pcVar4 == (char *)0x0) {
      _File->_base = (char *)&_File->_charbuf;
      _File->_ptr = (char *)&_File->_charbuf;
      _File->_bufsiz = 2;
      _File->_cnt = 2;
      goto LAB_3b40a908;
    }
  }
  pcVar4 = *ppcVar1;
  _File->_base = pcVar4;
  _File->_ptr = pcVar4;
  _File->_bufsiz = 0x1000;
  _File->_cnt = 0x1000;
LAB_3b40a908:
  _File->_flag = _File->_flag | 0x1102;
  return 1;
}



// Library Function - Single Match
//  __ftbuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __ftbuf(int _Flag,FILE *_File)

{
  if ((_Flag != 0) && ((_File->_flag & 0x1000U) != 0)) {
    __flush(_File);
    _File->_flag = _File->_flag & 0xffffeeff;
    _File->_bufsiz = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
  }
  return;
}



void FUN_3b40a9e2(void)

{
  FUN_3b40aa8c(1);
  return;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinitlocks(void)

{
  BOOL BVar1;
  int iVar2;
  LPCRITICAL_SECTION p_Var3;
  
  iVar2 = 0;
  p_Var3 = (LPCRITICAL_SECTION)&DAT_3b417ae8;
  do {
    if ((&DAT_3b416d94)[iVar2 * 2] == 1) {
      (&lpCriticalSection_3b416d90)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = InitializeCriticalSectionAndSpinCount((&lpCriticalSection_3b416d90)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&lpCriticalSection_3b416d90)[iVar2 * 2] = (LPCRITICAL_SECTION)0x0;
        return 0;
      }
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x24);
  return 1;
}



// Library Function - Single Match
//  __mtdeletelocks
// 
// Library: Visual Studio 2010 Release

void __cdecl __mtdeletelocks(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = &lpCriticalSection_3b416d90;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x3b416eb0);
  pp_Var1 = &lpCriticalSection_3b416d90;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x3b416eb0);
  return;
}



void __cdecl FUN_3b40aa8c(int param_1)

{
  LeaveCriticalSection((&lpCriticalSection_3b416d90)[param_1 * 2]);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __mtinitlocknum
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinitlocknum(int _LockNum)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  int *piVar2;
  BOOL BVar3;
  int iVar4;
  int local_20;
  
  iVar4 = 1;
  local_20 = 1;
  if (hHeap_3b417a7c == (HANDLE)0x0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = &lpCriticalSection_3b416d90 + _LockNum * 2;
  if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
    lpCriticalSection = (LPCRITICAL_SECTION)__malloc_crt(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      piVar2 = __errno();
      *piVar2 = 0xc;
      iVar4 = 0;
    }
    else {
      __lock(10);
      if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
        BVar3 = InitializeCriticalSectionAndSpinCount(lpCriticalSection,4000);
        if (BVar3 == 0) {
          _free(lpCriticalSection);
          piVar2 = __errno();
          *piVar2 = 0xc;
          local_20 = 0;
        }
        else {
          *pp_Var1 = lpCriticalSection;
        }
      }
      else {
        _free(lpCriticalSection);
      }
      FUN_3b40ab5c();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_3b40ab5c(void)

{
  FUN_3b40aa8c(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((&lpCriticalSection_3b416d90)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((&lpCriticalSection_3b416d90)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___check_float_string
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl ___check_float_string(size_t param_1,void *param_2,undefined4 *param_3)

{
  size_t _Count;
  void *pvVar1;
  size_t *unaff_ESI;
  void **unaff_EDI;
  
  _Count = *unaff_ESI;
  if (param_1 == _Count) {
    if (*unaff_EDI == param_2) {
      pvVar1 = __calloc_crt(_Count,2);
      *unaff_EDI = pvVar1;
      if (pvVar1 == (void *)0x0) {
        return 0;
      }
      *param_3 = 1;
      FID_conflict__memcpy(*unaff_EDI,param_2,*unaff_ESI);
    }
    else {
      pvVar1 = __recalloc_crt(*unaff_EDI,_Count,2);
      if (pvVar1 == (void *)0x0) {
        return 0;
      }
      *unaff_EDI = pvVar1;
    }
    *unaff_ESI = *unaff_ESI << 1;
  }
  return 1;
}



// Library Function - Single Match
//  __hextodec
// 
// Library: Visual Studio 2010 Release

uint __cdecl __hextodec(byte param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = _isdigit((uint)param_1);
  uVar2 = (uint)(char)param_1;
  if (iVar1 == 0) {
    uVar2 = (uVar2 & 0xffffffdf) - 7;
  }
  return uVar2;
}



// Library Function - Single Match
//  __inc
// 
// Library: Visual Studio 2010 Release

uint __fastcall __inc(undefined4 param_1,FILE *param_2)

{
  int *piVar1;
  byte bVar2;
  uint uVar3;
  
  piVar1 = &param_2->_cnt;
  *piVar1 = *piVar1 + -1;
  if (-1 < *piVar1) {
    bVar2 = *param_2->_ptr;
    param_2->_ptr = param_2->_ptr + 1;
    return (uint)bVar2;
  }
  uVar3 = __filbuf(param_2);
  return uVar3;
}



// Library Function - Single Match
//  __whiteout
// 
// Library: Visual Studio 2010 Release

uint __thiscall __whiteout(void *this,FILE *param_1)

{
  uint uVar1;
  int iVar2;
  int *unaff_ESI;
  
  do {
    *unaff_ESI = *unaff_ESI + 1;
    uVar1 = __inc(this,param_1);
    if (uVar1 == 0xffffffff) {
      return 0xffffffff;
    }
    this = (void *)(uVar1 & 0xff);
    iVar2 = _isspace((int)this);
  } while (iVar2 != 0);
  return uVar1;
}



// Library Function - Single Match
//  __input_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __input_l(FILE *_File,uchar *param_2,_locale_t _Locale,va_list _ArgList)

{
  byte bVar1;
  byte bVar2;
  int *piVar3;
  uint uVar4;
  code *pcVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  undefined *puVar10;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 uVar11;
  undefined4 extraout_ECX_04;
  FILE *extraout_ECX_05;
  FILE *pFVar12;
  FILE *extraout_ECX_06;
  FILE *extraout_ECX_07;
  FILE *extraout_ECX_08;
  undefined4 extraout_ECX_09;
  uint extraout_ECX_10;
  byte bVar13;
  void *_C;
  size_t sVar14;
  size_t sVar15;
  byte *pbVar16;
  uint uVar17;
  int *piVar18;
  byte *pbVar19;
  bool bVar20;
  longlong lVar21;
  int **local_204;
  localeinfo_struct local_200;
  int local_1f8;
  char local_1f4;
  undefined4 local_1f0;
  int **local_1ec;
  int local_1e8;
  byte local_1e4;
  undefined local_1e3;
  undefined4 local_1e0;
  int local_1dc;
  byte local_1d5;
  int local_1d4;
  int local_1d0;
  undefined8 local_1cc;
  int *local_1c4;
  byte *local_1c0;
  FILE *local_1bc;
  uint local_1b8;
  undefined *local_1b4;
  int local_1b0;
  byte local_1ac;
  char local_1ab;
  char local_1aa;
  char local_1a9;
  FILE *local_1a8;
  char local_1a1;
  int local_1a0;
  char local_199;
  uint local_198;
  char local_191;
  int local_190;
  byte local_189;
  undefined local_188 [352];
  byte local_28 [32];
  uint local_8;
  void *pvVar5;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  local_1ec = (int **)_ArgList;
  local_1b4 = local_188;
  local_1a8 = _File;
  local_1e0 = 0x15e;
  local_1d4 = 0;
  local_1f0 = 0;
  local_198 = 0;
  if ((param_2 == (uchar *)0x0) || (_File == (FILE *)0x0)) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_3b408343();
    goto LAB_3b40bc45;
  }
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    uVar4 = __fileno(_File);
    if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
      puVar10 = &DAT_3b4165d0;
    }
    else {
      puVar10 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar4 >> 5]);
    }
    if ((puVar10[0x24] & 0x7f) == 0) {
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar10 = &DAT_3b4165d0;
      }
      else {
        puVar10 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar4 >> 5]);
      }
      if ((puVar10[0x24] & 0x80) == 0) goto LAB_3b40ad3e;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_3b408343();
  }
  else {
LAB_3b40ad3e:
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_200,_Locale);
    bVar2 = *param_2;
    local_1a9 = '\0';
    local_190 = 0;
    local_1d0 = 0;
    if (bVar2 != 0) {
LAB_3b40ad6b:
      pvVar5 = (void *)(uint)bVar2;
      iVar9 = _isspace((int)pvVar5);
      if (iVar9 != 0) {
        local_190 = local_190 + -1;
        uVar4 = __whiteout(pvVar5,local_1a8);
        if (uVar4 != 0xffffffff) {
          __ungetc_nolock(uVar4,local_1a8);
        }
        do {
          param_2 = param_2 + 1;
          iVar9 = _isspace((uint)*param_2);
        } while (iVar9 != 0);
        goto LAB_3b40bba3;
      }
      if (*param_2 == 0x25) {
        if (param_2[1] == 0x25) {
          if (param_2[1] == 0x25) {
            param_2 = param_2 + 1;
          }
          goto LAB_3b40bb2d;
        }
        local_1e8 = 0;
        local_1d5 = 0;
        local_1b0 = 0;
        local_1bc = (FILE *)0x0;
        local_1a0 = 0;
        local_1ac = 0;
        local_1ab = '\0';
        local_1a1 = '\0';
        local_191 = '\0';
        local_1aa = '\0';
        local_199 = '\0';
        local_189 = 1;
        local_1dc = 0;
        do {
          pbVar16 = param_2 + 1;
          _C = (void *)(uint)*pbVar16;
          pvVar5 = _C;
          iVar9 = _isdigit((int)_C);
          pbVar19 = pbVar16;
          if (iVar9 == 0) {
            if (_C < (void *)0x4f) {
              if (_C != (void *)0x4e) {
                if (_C == (void *)0x2a) {
                  local_1a1 = local_1a1 + '\x01';
                }
                else if (_C != (void *)0x46) {
                  if (_C == (void *)0x49) {
                    bVar2 = param_2[2];
                    pvVar5 = (void *)CONCAT31((int3)((uint)pvVar5 >> 8),bVar2);
                    if ((bVar2 == 0x36) && (pbVar19 = param_2 + 3, *pbVar19 == 0x34))
                    goto LAB_3b40ae90;
                    if ((((((bVar2 != 0x33) || (pbVar19 = param_2 + 3, *pbVar19 != 0x32)) &&
                          (pbVar19 = pbVar16, bVar2 != 100)) && ((bVar2 != 0x69 && (bVar2 != 0x6f)))
                         ) && (bVar2 != 0x78)) && (bVar2 != 0x58)) goto LAB_3b40aee9;
                  }
                  else if (_C == (void *)0x4c) {
                    local_189 = local_189 + 1;
                  }
                  else {
LAB_3b40aee9:
                    local_191 = local_191 + '\x01';
                    pbVar19 = pbVar16;
                  }
                }
              }
            }
            else if (_C == (void *)0x68) {
              local_189 = local_189 - 1;
              local_199 = local_199 + -1;
            }
            else {
              if (_C == (void *)0x6c) {
                pbVar19 = param_2 + 2;
                if (*pbVar19 == 0x6c) {
LAB_3b40ae90:
                  local_1dc = local_1dc + 1;
                  local_1cc = 0;
                  goto LAB_3b40af13;
                }
                local_189 = local_189 + 1;
              }
              else if (_C != (void *)0x77) goto LAB_3b40aee9;
              local_199 = local_199 + '\x01';
              pbVar19 = pbVar16;
            }
          }
          else {
            local_1bc = (FILE *)((int)&local_1bc->_ptr + 1);
            local_1a0 = local_1a0 * 10 + -0x30 + (int)_C;
          }
LAB_3b40af13:
          param_2 = pbVar19;
        } while (local_191 == '\0');
        if (local_1a1 == '\0') {
          local_1c4 = *local_1ec;
          local_204 = local_1ec;
          local_1ec = local_1ec + 1;
        }
        else {
          local_1c4 = (int *)0x0;
        }
        local_191 = '\0';
        if ((local_199 == '\0') && ((*pbVar19 == 0x53 || (local_199 = -1, *pbVar19 == 0x43)))) {
          local_199 = '\x01';
        }
        uVar4 = *pbVar19 | 0x20;
        local_1c0 = pbVar19;
        local_1b8 = uVar4;
        if (uVar4 != 0x6e) {
          if ((uVar4 == 99) || (uVar4 == 0x7b)) {
            local_190 = local_190 + 1;
            local_198 = __inc(pvVar5,local_1a8);
          }
          else {
            local_198 = __whiteout(pvVar5,local_1a8);
          }
          if (local_198 == 0xffffffff) goto LAB_3b40bbe3;
        }
        pFVar12 = local_1bc;
        uVar7 = local_198;
        if ((local_1bc != (FILE *)0x0) && (local_1a0 == 0)) goto LAB_3b40bbce;
        if (uVar4 < 0x70) {
          if (uVar4 == 0x6f) {
LAB_3b40b858:
            if (local_198 == 0x2d) {
              local_1ab = '\x01';
            }
            else if (local_198 != 0x2b) goto LAB_3b40b89f;
            local_1a0 = local_1a0 + -1;
            if ((local_1a0 == 0) && (local_1bc != (FILE *)0x0)) {
              local_191 = '\x01';
            }
            else {
              local_190 = local_190 + 1;
              local_198 = __inc(local_1bc,local_1a8);
            }
            goto LAB_3b40b89f;
          }
          if (uVar4 == 99) {
            if (local_1bc == (FILE *)0x0) {
              local_1a0 = local_1a0 + 1;
              local_1bc = (FILE *)0x1;
            }
LAB_3b40b42b:
            if ('\0' < local_199) {
              local_1aa = '\x01';
            }
LAB_3b40b43b:
            piVar3 = local_1c4;
            local_190 = local_190 + -1;
            piVar18 = piVar3;
            if (local_198 != 0xffffffff) {
              pFVar12 = local_1a8;
              __ungetc_nolock(local_198,local_1a8);
            }
            do {
              if ((local_1bc != (FILE *)0x0) &&
                 (iVar9 = local_1a0 + -1, bVar20 = local_1a0 == 0, local_1a0 = iVar9, bVar20))
              goto LAB_3b40b806;
              local_190 = local_190 + 1;
              local_198 = __inc(pFVar12,local_1a8);
              if (local_198 == 0xffffffff) goto LAB_3b40b7ed;
              bVar2 = (byte)local_198;
              pFVar12 = extraout_ECX_05;
              if (uVar4 != 99) {
                if (uVar4 == 0x73) {
                  if ((8 < (int)local_198) && ((int)local_198 < 0xe)) goto LAB_3b40b7ed;
                  if (local_198 != 0x20) goto LAB_3b40b4ed;
                }
                if ((uVar4 != 0x7b) ||
                   (pFVar12 = (FILE *)(int)(char)(local_28[(int)local_198 >> 3] ^ local_1ac),
                   uVar4 = local_1b8, ((uint)pFVar12 & 1 << (bVar2 & 7)) == 0)) goto LAB_3b40b7ed;
              }
LAB_3b40b4ed:
              if (local_1a1 == '\0') {
                if (local_1aa == '\0') {
                  *(byte *)piVar3 = bVar2;
                  piVar3 = (int *)((int)piVar3 + 1);
                  local_1c4 = piVar3;
                }
                else {
                  uVar7 = local_198 & 0xff;
                  local_1e4 = bVar2;
                  iVar9 = _isleadbyte(uVar7);
                  if (iVar9 != 0) {
                    local_190 = local_190 + 1;
                    uVar7 = __inc(uVar7,local_1a8);
                    local_1e3 = (undefined)uVar7;
                  }
                  local_1f0 = 0x3f;
                  __mbtowc_l((wchar_t *)&local_1f0,(char *)&local_1e4,
                             (size_t)(local_200.locinfo)->locale_name[3],&local_200);
                  *(undefined2 *)piVar3 = (undefined2)local_1f0;
                  piVar3 = (int *)((int)piVar3 + 2);
                  pFVar12 = extraout_ECX_06;
                  local_1c4 = piVar3;
                }
              }
              else {
                piVar18 = (int *)((int)piVar18 + 1);
              }
            } while( true );
          }
          if (uVar4 == 100) goto LAB_3b40b858;
          if (uVar4 < 0x65) {
LAB_3b40b5a1:
            if (*local_1c0 != local_198) goto LAB_3b40bbce;
            local_1a9 = local_1a9 + -1;
            if (local_1a1 == '\0') {
              local_1ec = local_204;
            }
            goto LAB_3b40bb0e;
          }
          if (0x67 < uVar4) {
            if (uVar4 == 0x69) {
              local_1b8 = 100;
              goto LAB_3b40b044;
            }
            if (uVar4 != 0x6e) goto LAB_3b40b5a1;
            iVar9 = local_190;
            if (local_1a1 != '\0') goto LAB_3b40bb0e;
            goto LAB_3b40bae2;
          }
          sVar14 = 0;
          if (local_198 == 0x2d) {
            *local_1b4 = 0x2d;
            sVar14 = 1;
LAB_3b40b07f:
            local_1a0 = local_1a0 + -1;
            local_190 = local_190 + 1;
            local_198 = __inc(local_1bc,local_1a8);
          }
          else if (local_198 == 0x2b) goto LAB_3b40b07f;
          if (local_1bc == (FILE *)0x0) {
            local_1a0 = -1;
          }
          while( true ) {
            uVar4 = local_198 & 0xff;
            iVar9 = _isdigit(uVar4);
            if ((iVar9 == 0) ||
               (iVar9 = local_1a0 + -1, bVar20 = local_1a0 == 0, local_1a0 = iVar9, bVar20)) break;
            local_1b0 = local_1b0 + 1;
            local_1b4[sVar14] = (byte)local_198;
            sVar14 = sVar14 + 1;
            iVar9 = ___check_float_string(sVar14,local_188,&local_1d4);
            if (iVar9 == 0) goto LAB_3b40bbe3;
            local_190 = local_190 + 1;
            local_198 = __inc(extraout_ECX,local_1a8);
          }
          local_1ac = **(byte **)local_200.locinfo[1].lc_codepage;
          if ((local_1ac == (byte)local_198) &&
             (iVar9 = local_1a0 + -1, bVar20 = local_1a0 != 0, local_1a0 = iVar9, bVar20)) {
            local_190 = local_190 + 1;
            local_198 = __inc(uVar4,local_1a8);
            local_1b4[sVar14] = local_1ac;
            sVar14 = sVar14 + 1;
            iVar9 = ___check_float_string(sVar14,local_188,&local_1d4);
            if (iVar9 == 0) goto LAB_3b40bbe3;
            while ((iVar9 = _isdigit(local_198 & 0xff), iVar9 != 0 &&
                   (iVar9 = local_1a0 + -1, bVar20 = local_1a0 != 0, local_1a0 = iVar9, bVar20))) {
              local_1b0 = local_1b0 + 1;
              local_1b4[sVar14] = (byte)local_198;
              sVar14 = sVar14 + 1;
              iVar9 = ___check_float_string(sVar14,local_188,&local_1d4);
              if (iVar9 == 0) goto LAB_3b40bbe3;
              local_190 = local_190 + 1;
              local_198 = __inc(extraout_ECX_00,local_1a8);
            }
          }
          sVar15 = sVar14;
          if ((local_1b0 != 0) &&
             (((local_198 == 0x65 || (local_198 == 0x45)) &&
              (iVar9 = local_1a0 + -1, bVar20 = local_1a0 != 0, local_1a0 = iVar9, bVar20)))) {
            local_1b4[sVar14] = 0x65;
            sVar15 = sVar14 + 1;
            iVar9 = ___check_float_string(sVar15,local_188,&local_1d4);
            if (iVar9 == 0) goto LAB_3b40bbe3;
            local_190 = local_190 + 1;
            local_198 = __inc(extraout_ECX_01,local_1a8);
            if (local_198 == 0x2d) {
              local_1b4[sVar15] = 0x2d;
              sVar15 = sVar14 + 2;
              iVar9 = ___check_float_string(sVar15,local_188,&local_1d4);
              uVar11 = extraout_ECX_03;
              if (iVar9 == 0) goto LAB_3b40bbe3;
LAB_3b40b2f0:
              if (local_1a0 == 0) {
                local_1a0 = 0;
              }
              else {
                local_190 = local_190 + 1;
                local_1a0 = local_1a0 + -1;
                local_198 = __inc(uVar11,local_1a8);
              }
            }
            else {
              uVar11 = extraout_ECX_02;
              if (local_198 == 0x2b) goto LAB_3b40b2f0;
            }
            while ((iVar9 = _isdigit(local_198 & 0xff), iVar9 != 0 &&
                   (iVar9 = local_1a0 + -1, bVar20 = local_1a0 != 0, local_1a0 = iVar9, bVar20))) {
              local_1b0 = local_1b0 + 1;
              local_1b4[sVar15] = (byte)local_198;
              sVar15 = sVar15 + 1;
              iVar9 = ___check_float_string(sVar15,local_188,&local_1d4);
              if (iVar9 == 0) goto LAB_3b40bbe3;
              local_190 = local_190 + 1;
              local_198 = __inc(extraout_ECX_04,local_1a8);
            }
          }
          local_190 = local_190 + -1;
          if (local_198 != 0xffffffff) {
            __ungetc_nolock(local_198,local_1a8);
          }
          if (local_1b0 != 0) {
            if (local_1a1 == '\0') {
              local_1d0 = local_1d0 + 1;
              local_1b4[sVar15] = 0;
              pcVar6 = (code *)(*(code *)PTR_FUN_3b416004)
                                         (PTR_LAB_3b416edc,(char)local_189 + -1,local_1c4,local_1b4,
                                          &local_200);
              (*pcVar6)();
            }
            goto LAB_3b40bb0e;
          }
          goto LAB_3b40bbe3;
        }
        if (uVar4 == 0x70) {
          local_189 = 1;
          goto LAB_3b40b858;
        }
        if (uVar4 == 0x73) goto LAB_3b40b42b;
        if (uVar4 == 0x75) goto LAB_3b40b858;
        if (uVar4 != 0x78) {
          if (uVar4 == 0x7b) {
            if ('\0' < local_199) {
              local_1aa = '\x01';
            }
            pbVar19 = local_1c0 + 1;
            if (local_1c0[1] == 0x5e) {
              pbVar19 = local_1c0 + 2;
              local_1ac = 0xff;
            }
            _memset(local_28,0,0x20);
            pFVar12 = extraout_ECX_07;
            bVar2 = local_1d5;
            if (*pbVar19 == 0x5d) {
              local_28[11] = 0x20;
              pbVar19 = pbVar19 + 1;
              bVar2 = 0x5d;
            }
            while( true ) {
              bVar13 = *pbVar19;
              local_1c0 = pbVar19;
              if (bVar13 == 0x5d) break;
              if (((bVar13 == 0x2d) && (bVar2 != 0)) && (bVar1 = pbVar19[1], bVar1 != 0x5d)) {
                bVar13 = bVar1;
                local_189 = bVar2;
                if (bVar2 < bVar1) {
                  bVar13 = bVar2;
                  local_189 = bVar1;
                }
                if (bVar13 < local_189) {
                  uVar17 = (uint)bVar13;
                  uVar7 = (uint)(byte)(local_189 - bVar13);
                  do {
                    local_28[uVar17 >> 3] = local_28[uVar17 >> 3] | '\x01' << ((byte)uVar17 & 7);
                    uVar17 = uVar17 + 1;
                    uVar7 = uVar7 - 1;
                    uVar4 = local_1b8;
                  } while (uVar7 != 0);
                }
                pFVar12 = (FILE *)(local_189 & 7);
                local_28[local_189 >> 3] = local_28[local_189 >> 3] | '\x01' << (sbyte)pFVar12;
                pbVar19 = pbVar19 + 2;
                bVar2 = 0;
              }
              else {
                pFVar12 = (FILE *)(bVar13 & 7);
                local_28[bVar13 >> 3] = local_28[bVar13 >> 3] | '\x01' << (sbyte)pFVar12;
                uVar4 = local_1b8;
                pbVar19 = pbVar19 + 1;
                bVar2 = bVar13;
              }
            }
            goto LAB_3b40b43b;
          }
          goto LAB_3b40b5a1;
        }
LAB_3b40b044:
        if (local_198 == 0x2d) {
          local_1ab = '\x01';
LAB_3b40b6de:
          local_1a0 = local_1a0 + -1;
          if ((local_1a0 == 0) && (local_1bc != (FILE *)0x0)) {
            local_191 = '\x01';
          }
          else {
            local_190 = local_190 + 1;
            local_198 = __inc(local_1bc,local_1a8);
            pFVar12 = extraout_ECX_08;
          }
        }
        else if (local_198 == 0x2b) goto LAB_3b40b6de;
        if (local_198 == 0x30) {
          local_190 = local_190 + 1;
          local_198 = __inc(pFVar12,local_1a8);
          if (((char)local_198 == 'x') || ((char)local_198 == 'X')) {
            local_190 = local_190 + 1;
            local_198 = __inc(extraout_ECX_09,local_1a8);
            if ((local_1bc != (FILE *)0x0) && (local_1a0 = local_1a0 + -2, local_1a0 < 1)) {
              local_191 = local_191 + '\x01';
            }
            local_1b8 = 0x78;
          }
          else {
            local_1b0 = 1;
            if (local_1b8 == 0x78) {
              local_190 = local_190 + -1;
              if (local_198 != 0xffffffff) {
                __ungetc_nolock(local_198,local_1a8);
              }
              local_198 = 0x30;
            }
            else {
              if ((local_1bc != (FILE *)0x0) && (local_1a0 = local_1a0 + -1, local_1a0 == 0)) {
                local_191 = local_191 + '\x01';
              }
              local_1b8 = 0x6f;
            }
          }
        }
LAB_3b40b89f:
        if (local_1dc == 0) {
          iVar9 = local_1e8;
          if (local_191 == '\0') {
            while ((uVar4 = local_198, local_1b8 != 0x78 && (local_1b8 != 0x70))) {
              uVar7 = local_198 & 0xff;
              iVar8 = _isdigit(uVar7);
              if (iVar8 == 0) goto LAB_3b40ba8c;
              if (local_1b8 == 0x6f) {
                if (0x37 < (int)uVar4) goto LAB_3b40ba8c;
                iVar9 = iVar9 << 3;
              }
              else {
                iVar9 = iVar9 * 10;
              }
LAB_3b40ba53:
              local_1b0 = local_1b0 + 1;
              iVar9 = iVar9 + -0x30 + uVar4;
              if ((local_1bc != (FILE *)0x0) && (local_1a0 = local_1a0 + -1, local_1a0 == 0))
              goto LAB_3b40baa5;
              local_190 = local_190 + 1;
              local_198 = __inc(uVar7,local_1a8);
            }
            iVar8 = _isxdigit(local_198 & 0xff);
            if (iVar8 != 0) {
              iVar9 = iVar9 << 4;
              uVar7 = uVar4;
              uVar4 = __hextodec((byte)uVar4);
              local_198 = uVar4;
              goto LAB_3b40ba53;
            }
LAB_3b40ba8c:
            local_190 = local_190 + -1;
            if (uVar4 != 0xffffffff) {
              __ungetc_nolock(uVar4,local_1a8);
            }
          }
LAB_3b40baa5:
          if (local_1ab != '\0') {
            iVar9 = -iVar9;
          }
        }
        else {
          if (local_191 == '\0') {
            while ((uVar4 = local_198, local_1b8 != 0x78 && (local_1b8 != 0x70))) {
              uVar7 = local_198 & 0xff;
              iVar9 = _isdigit(uVar7);
              if (iVar9 == 0) goto LAB_3b40b998;
              if (local_1b8 == 0x6f) {
                if (0x37 < (int)uVar4) goto LAB_3b40b998;
                lVar21 = CONCAT44(local_1cc._4_4_ << 3 | (uint)local_1cc >> 0x1d,
                                  (uint)local_1cc << 3);
              }
              else {
                lVar21 = __allmul((uint)local_1cc,local_1cc._4_4_,10,0);
                uVar7 = extraout_ECX_10;
              }
LAB_3b40b94f:
              local_1b0 = local_1b0 + 1;
              local_1cc = lVar21 + (int)(uVar4 - 0x30);
              if ((local_1bc != (FILE *)0x0) && (local_1a0 = local_1a0 + -1, local_1a0 == 0))
              goto LAB_3b40b9b1;
              local_190 = local_190 + 1;
              local_198 = __inc(uVar7,local_1a8);
            }
            iVar9 = _isxdigit(local_198 & 0xff);
            if (iVar9 != 0) {
              lVar21 = CONCAT44(local_1cc._4_4_ << 4 | (uint)local_1cc >> 0x1c,(uint)local_1cc << 4)
              ;
              uVar7 = uVar4;
              uVar4 = __hextodec((byte)uVar4);
              local_198 = uVar4;
              goto LAB_3b40b94f;
            }
LAB_3b40b998:
            local_190 = local_190 + -1;
            if (uVar4 != 0xffffffff) {
              __ungetc_nolock(uVar4,local_1a8);
            }
          }
LAB_3b40b9b1:
          iVar9 = local_1e8;
          if (local_1ab != '\0') {
            local_1cc = CONCAT44(-(local_1cc._4_4_ + ((uint)local_1cc != 0)),-(uint)local_1cc);
          }
        }
        if (local_1b8 == 0x46) {
          local_1b0 = 0;
        }
        if (local_1b0 == 0) goto LAB_3b40bbe3;
        if (local_1a1 == '\0') {
          local_1d0 = local_1d0 + 1;
LAB_3b40bae2:
          if (local_1dc == 0) {
            if (local_189 == 0) {
              *(short *)local_1c4 = (short)iVar9;
            }
            else {
              *local_1c4 = iVar9;
            }
          }
          else {
            *local_1c4 = (uint)local_1cc;
            local_1c4[1] = local_1cc._4_4_;
          }
        }
LAB_3b40bb0e:
        local_1a9 = local_1a9 + '\x01';
        pbVar19 = local_1c0 + 1;
        local_1c0 = pbVar19;
LAB_3b40bb87:
        param_2 = pbVar19;
        if ((local_198 == 0xffffffff) &&
           ((*pbVar19 != 0x25 || (param_2 = local_1c0, local_1c0[1] != 0x6e)))) goto LAB_3b40bbe3;
LAB_3b40bba3:
        bVar2 = *param_2;
        if (bVar2 == 0) goto LAB_3b40bbe3;
        goto LAB_3b40ad6b;
      }
LAB_3b40bb2d:
      local_190 = local_190 + 1;
      uVar7 = __inc(pvVar5,local_1a8);
      pbVar19 = param_2 + 1;
      local_1c0 = pbVar19;
      local_198 = uVar7;
      if (*param_2 == uVar7) {
        uVar4 = uVar7 & 0xff;
        iVar9 = _isleadbyte(uVar4);
        if (iVar9 != 0) {
          local_190 = local_190 + 1;
          uVar4 = __inc(uVar4,local_1a8);
          bVar2 = *pbVar19;
          pbVar19 = param_2 + 2;
          local_1c0 = pbVar19;
          if (bVar2 != uVar4) {
            if (uVar4 != 0xffffffff) {
              __ungetc_nolock(uVar4,local_1a8);
            }
            goto LAB_3b40bbce;
          }
          local_190 = local_190 + -1;
        }
        goto LAB_3b40bb87;
      }
LAB_3b40bbce:
      if (uVar7 != 0xffffffff) {
        __ungetc_nolock(local_198,local_1a8);
      }
LAB_3b40bbe3:
      if (local_1d4 == 1) {
        _free(local_1b4);
      }
      if (local_198 == 0xffffffff) {
        if (local_1f4 != '\0') {
          *(uint *)(local_1f8 + 0x70) = *(uint *)(local_1f8 + 0x70) & 0xfffffffd;
        }
        goto LAB_3b40bc45;
      }
    }
    if (local_1f4 != '\0') {
      *(uint *)(local_1f8 + 0x70) = *(uint *)(local_1f8 + 0x70) & 0xfffffffd;
    }
  }
LAB_3b40bc45:
  iVar9 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar9;
LAB_3b40b7ed:
  local_190 = local_190 + -1;
  if (local_198 != 0xffffffff) {
    __ungetc_nolock(local_198,local_1a8);
  }
LAB_3b40b806:
  if (piVar18 == piVar3) goto LAB_3b40bbe3;
  if ((local_1a1 == '\0') && (local_1d0 = local_1d0 + 1, uVar4 != 99)) {
    if (local_1aa == '\0') {
      *(undefined *)local_1c4 = 0;
    }
    else {
      *(undefined2 *)local_1c4 = 0;
    }
  }
  goto LAB_3b40bb0e;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Library: Visual Studio 2010 Release

int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (_MaxCount != 0) {
    do {
      bVar2 = *_Str1;
      cVar1 = *_Str2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = _Str2 + 1;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar4 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
      }
      uVar3 = (ushort)uVar4;
      bVar2 = (byte)uVar4;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar3 = (ushort)CONCAT31((int3)(uVar4 >> 8),bVar2 + 0x20);
      }
      bVar2 = (byte)(uVar3 >> 8);
      bVar5 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) goto LAB_3b40bcb1;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_3b40bcb1:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setenvp
// 
// Library: Visual Studio 2010 Release

int __cdecl __setenvp(void)

{
  char **ppcVar1;
  size_t sVar2;
  char *_Dst;
  errno_t eVar3;
  char *pcVar4;
  int iVar5;
  
  if (DAT_3b41820c == 0) {
    ___initmbctable();
  }
  iVar5 = 0;
  pcVar4 = environmentStrings;
  if (environmentStrings != (char *)0x0) {
    for (; *pcVar4 != '\0'; pcVar4 = pcVar4 + sVar2 + 1) {
      if (*pcVar4 != '=') {
        iVar5 = iVar5 + 1;
      }
      sVar2 = _strlen(pcVar4);
    }
    ppcVar1 = (char **)__calloc_crt(iVar5 + 1,4);
    pcVar4 = environmentStrings;
    DAT_3b417a90 = ppcVar1;
    if (ppcVar1 != (char **)0x0) {
      do {
        if (*pcVar4 == '\0') {
          _free(environmentStrings);
          environmentStrings = (char *)0x0;
          *ppcVar1 = (char *)0x0;
          _DAT_3b418200 = 1;
          return 0;
        }
        sVar2 = _strlen(pcVar4);
        sVar2 = sVar2 + 1;
        if (*pcVar4 != '=') {
          _Dst = (char *)__calloc_crt(sVar2,1);
          *ppcVar1 = _Dst;
          if (_Dst == (char *)0x0) {
            _free(DAT_3b417a90);
            DAT_3b417a90 = (char **)0x0;
            return -1;
          }
          eVar3 = _strcpy_s(_Dst,sVar2,pcVar4);
          if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          ppcVar1 = ppcVar1 + 1;
        }
        pcVar4 = pcVar4 + sVar2;
      } while( true );
    }
  }
  return -1;
}



// Library Function - Single Match
//  _parse_cmdline
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall
_parse_cmdline(undefined4 param_1,byte *param_2,byte **param_3,byte *param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  byte bVar6;
  byte *pbVar7;
  byte *pbVar8;
  int *unaff_EDI;
  
  *unaff_EDI = 0;
  *param_5 = 1;
  if (param_3 != (byte **)0x0) {
    *param_3 = param_4;
    param_3 = param_3 + 1;
  }
  bVar2 = false;
  pbVar5 = param_4;
  do {
    if (*param_2 == 0x22) {
      bVar2 = !bVar2;
      bVar6 = 0x22;
      pbVar7 = param_2 + 1;
    }
    else {
      *unaff_EDI = *unaff_EDI + 1;
      if (pbVar5 != (byte *)0x0) {
        *pbVar5 = *param_2;
        param_4 = pbVar5 + 1;
      }
      bVar6 = *param_2;
      pbVar7 = param_2 + 1;
      iVar3 = __ismbblead((uint)bVar6);
      if (iVar3 != 0) {
        *unaff_EDI = *unaff_EDI + 1;
        if (param_4 != (byte *)0x0) {
          *param_4 = *pbVar7;
          param_4 = param_4 + 1;
        }
        pbVar7 = param_2 + 2;
      }
      pbVar5 = param_4;
      if (bVar6 == 0) {
        pbVar7 = pbVar7 + -1;
        goto LAB_3b40be31;
      }
    }
    param_2 = pbVar7;
  } while ((bVar2) || ((bVar6 != 0x20 && (bVar6 != 9))));
  if (pbVar5 != (byte *)0x0) {
    pbVar5[-1] = 0;
  }
LAB_3b40be31:
  bVar2 = false;
  while (*pbVar7 != 0) {
    for (; (*pbVar7 == 0x20 || (*pbVar7 == 9)); pbVar7 = pbVar7 + 1) {
    }
    if (*pbVar7 == 0) break;
    if (param_3 != (byte **)0x0) {
      *param_3 = pbVar5;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
    while( true ) {
      bVar1 = true;
      uVar4 = 0;
      for (; *pbVar7 == 0x5c; pbVar7 = pbVar7 + 1) {
        uVar4 = uVar4 + 1;
      }
      if (*pbVar7 == 0x22) {
        pbVar8 = pbVar7;
        if (((uVar4 & 1) == 0) && ((!bVar2 || (pbVar8 = pbVar7 + 1, *pbVar8 != 0x22)))) {
          bVar1 = false;
          bVar2 = !bVar2;
          pbVar8 = pbVar7;
        }
        uVar4 = uVar4 >> 1;
        pbVar7 = pbVar8;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (pbVar5 != (byte *)0x0) {
          *pbVar5 = 0x5c;
          pbVar5 = pbVar5 + 1;
        }
        *unaff_EDI = *unaff_EDI + 1;
        param_4 = pbVar5;
      }
      bVar6 = *pbVar7;
      if ((bVar6 == 0) || ((!bVar2 && ((bVar6 == 0x20 || (bVar6 == 9)))))) break;
      if (bVar1) {
        if (pbVar5 == (byte *)0x0) {
          iVar3 = __ismbblead((int)(char)bVar6);
          if (iVar3 != 0) {
            pbVar7 = pbVar7 + 1;
            *unaff_EDI = *unaff_EDI + 1;
          }
        }
        else {
          iVar3 = __ismbblead((int)(char)bVar6);
          if (iVar3 != 0) {
            *param_4 = *pbVar7;
            pbVar7 = pbVar7 + 1;
            *unaff_EDI = *unaff_EDI + 1;
            param_4 = param_4 + 1;
          }
          *param_4 = *pbVar7;
          param_4 = param_4 + 1;
        }
        *unaff_EDI = *unaff_EDI + 1;
        pbVar5 = param_4;
      }
      pbVar7 = pbVar7 + 1;
    }
    if (pbVar5 != (byte *)0x0) {
      *pbVar5 = 0;
      pbVar5 = pbVar5 + 1;
      param_4 = pbVar5;
    }
    *unaff_EDI = *unaff_EDI + 1;
  }
  if (param_3 != (byte **)0x0) {
    *param_3 = (byte *)0x0;
  }
  *param_5 = *param_5 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setargv
// 
// Library: Visual Studio 2010 Release

int __cdecl __setargv(void)

{
  uint uVar1;
  byte **ppbVar2;
  undefined4 extraout_ECX;
  uint _Size;
  uint local_10;
  uint local_c;
  byte *local_8;
  
  if (DAT_3b41820c == 0) {
    ___initmbctable();
  }
  DAT_3b417d3c = 0;
  GetModuleFileNameA((HMODULE)0x0,&DAT_3b417c38,0x104);
  _DAT_3b417aa0 = &DAT_3b417c38;
  if ((commandLineArgs == (byte *)0x0) || (local_8 = commandLineArgs, *commandLineArgs == 0)) {
    local_8 = &DAT_3b417c38;
  }
  _parse_cmdline(extraout_ECX,local_8,(byte **)0x0,(byte *)0x0,(int *)&local_c);
  uVar1 = local_c;
  if ((local_c < 0x3fffffff) && (local_10 != 0xffffffff)) {
    _Size = local_c * 4 + local_10;
    if ((local_10 <= _Size) && (ppbVar2 = (byte **)__malloc_crt(_Size), ppbVar2 != (byte **)0x0)) {
      _parse_cmdline(_Size,local_8,ppbVar2,(byte *)(ppbVar2 + uVar1),(int *)&local_c);
      _DAT_3b417a84 = local_c - 1;
      _DAT_3b417a88 = ppbVar2;
      return 0;
    }
  }
  return -1;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsA
// 
// Library: Visual Studio 2010 Release

LPVOID __cdecl ___crtGetEnvironmentStringsA(void)

{
  WCHAR WVar1;
  LPWCH lpWideCharStr;
  WCHAR *pWVar2;
  int iVar4;
  size_t _Size;
  LPSTR local_8;
  WCHAR *pWVar3;
  
  lpWideCharStr = GetEnvironmentStringsW();
  if (lpWideCharStr == (LPWCH)0x0) {
    local_8 = (LPSTR)0x0;
  }
  else {
    WVar1 = *lpWideCharStr;
    pWVar2 = lpWideCharStr;
    while (WVar1 != L'\0') {
      do {
        pWVar3 = pWVar2;
        pWVar2 = pWVar3 + 1;
      } while (*pWVar2 != L'\0');
      pWVar2 = pWVar3 + 2;
      WVar1 = *pWVar2;
    }
    iVar4 = ((int)pWVar2 - (int)lpWideCharStr >> 1) + 1;
    _Size = WideCharToMultiByte(0,0,lpWideCharStr,iVar4,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    if ((_Size == 0) || (local_8 = (LPSTR)__malloc_crt(_Size), local_8 == (LPSTR)0x0)) {
      FreeEnvironmentStringsW(lpWideCharStr);
      local_8 = (LPSTR)0x0;
    }
    else {
      iVar4 = WideCharToMultiByte(0,0,lpWideCharStr,iVar4,local_8,_Size,(LPCSTR)0x0,(LPBOOL)0x0);
      if (iVar4 == 0) {
        _free(local_8);
        local_8 = (LPSTR)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
    }
  }
  return local_8;
}



// WARNING: Removing unreachable block (ram,0x3b40c09f)
// WARNING: Removing unreachable block (ram,0x3b40c0a5)
// WARNING: Removing unreachable block (ram,0x3b40c0a7)
// Library Function - Single Match
//  __RTC_Initialize
// 
// Library: Visual Studio 2010 Release

void __RTC_Initialize(void)

{
  return;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2010 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  void *pvVar3;
  ulong uVar4;
  _ptiddata p_Var5;
  ulong *puVar6;
  int iVar7;
  
  p_Var5 = __getptd_noexit();
  if (p_Var5 != (_ptiddata)0x0) {
    puVar1 = (ulong *)p_Var5->_pxcptacttab;
    puVar6 = puVar1;
    do {
      if (*puVar6 == _ExceptionNum) break;
      puVar6 = puVar6 + 3;
    } while (puVar6 < puVar1 + 0x24);
    if ((puVar1 + 0x24 <= puVar6) || (*puVar6 != _ExceptionNum)) {
      puVar6 = (ulong *)0x0;
    }
    if ((puVar6 == (ulong *)0x0) || (pcVar2 = (code *)puVar6[2], pcVar2 == (code *)0x0)) {
      p_Var5 = (_ptiddata)0x0;
    }
    else if (pcVar2 == (code *)0x5) {
      puVar6[2] = 0;
      p_Var5 = (_ptiddata)0x1;
    }
    else {
      if (pcVar2 != (code *)0x1) {
        pvVar3 = p_Var5->_tpxcptinfoptrs;
        p_Var5->_tpxcptinfoptrs = _ExceptionPtr;
        if (puVar6[1] == 8) {
          iVar7 = 0x24;
          do {
            *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
            iVar7 = iVar7 + 0xc;
          } while (iVar7 < 0x90);
          uVar4 = *puVar6;
          iVar7 = p_Var5->_tfpecode;
          if (uVar4 == 0xc000008e) {
            p_Var5->_tfpecode = 0x83;
          }
          else if (uVar4 == 0xc0000090) {
            p_Var5->_tfpecode = 0x81;
          }
          else if (uVar4 == 0xc0000091) {
            p_Var5->_tfpecode = 0x84;
          }
          else if (uVar4 == 0xc0000093) {
            p_Var5->_tfpecode = 0x85;
          }
          else if (uVar4 == 0xc000008d) {
            p_Var5->_tfpecode = 0x82;
          }
          else if (uVar4 == 0xc000008f) {
            p_Var5->_tfpecode = 0x86;
          }
          else if (uVar4 == 0xc0000092) {
            p_Var5->_tfpecode = 0x8a;
          }
          else if (uVar4 == 0xc00002b5) {
            p_Var5->_tfpecode = 0x8d;
          }
          else if (uVar4 == 0xc00002b4) {
            p_Var5->_tfpecode = 0x8e;
          }
          (*pcVar2)(8,p_Var5->_tfpecode);
          p_Var5->_tfpecode = iVar7;
        }
        else {
          puVar6[2] = 0;
          (*pcVar2)(puVar6[1]);
        }
        p_Var5->_tpxcptinfoptrs = pvVar3;
      }
      p_Var5 = (_ptiddata)0xffffffff;
    }
  }
  return (int)p_Var5;
}



// Library Function - Single Match
//  ___CppXcptFilter
// 
// Library: Visual Studio 2010 Release

int __cdecl ___CppXcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  int iVar1;
  
  if (_ExceptionNum == 0xe06d7363) {
    iVar1 = __XcptFilter(0xe06d7363,_ExceptionPtr);
    return iVar1;
  }
  return 0;
}



undefined4 performInitialization(void)

{
  return 1;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2010 Release

void __cdecl ___security_init_cookie(void)

{
  DWORD processId;
  DWORD threadId;
  DWORD tickCount;
  uint xorResult;
  LARGE_INTEGER performanceCounter;
  _FILETIME systemTime;
  
  systemTime.dwLowDateTime = 0;
  systemTime.dwHighDateTime = 0;
  if ((securityCookie == 0xbb40e64e) || ((securityCookie & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&systemTime);
    xorResult = systemTime.dwHighDateTime ^ systemTime.dwLowDateTime;
    processId = GetCurrentProcessId();
    threadId = GetCurrentThreadId();
    tickCount = GetTickCount();
    QueryPerformanceCounter(&performanceCounter);
    securityCookie =
         xorResult ^ processId ^ threadId ^ tickCount ^
         performanceCounter.s.HighPart ^ performanceCounter.s.LowPart;
    if (securityCookie == 0xbb40e64e) {
      securityCookie = 0xbb40e64f;
    }
    else if ((securityCookie & 0xffff0000) == 0) {
      securityCookie = securityCookie | (securityCookie | 0x4711) << 0x10;
    }
    invertedSecurityCookie = ~securityCookie;
  }
  else {
    invertedSecurityCookie = ~securityCookie;
  }
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2010 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_3b417d7c = param_1;
  DAT_3b417d80 = param_1;
  DAT_3b417d84 = param_1;
  DAT_3b417d88 = param_1;
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 2010 Release

uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < param_3 + 0x90);
  if ((param_3 + 0x90 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_3b40c337(void)

{
  (*(code *)PTR_FUN_3b416004)(DAT_3b417d84);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2010 Release

int __cdecl _raise(int _SigNum)

{
  bool bVar1;
  uint uVar2;
  int *piVar3;
  undefined4 uVar4;
  code *pcVar5;
  code *pcVar6;
  undefined4 extraout_ECX;
  code **ppcVar7;
  _ptiddata p_Var8;
  int local_34;
  void *local_30;
  int local_28;
  
  p_Var8 = (_ptiddata)0x0;
  bVar1 = false;
  if (_SigNum < 0xc) {
    if (_SigNum != 0xb) {
      if (_SigNum == 2) {
        ppcVar7 = (code **)&DAT_3b417d7c;
        uVar4 = DAT_3b417d7c;
        goto LAB_3b40c3ee;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_3b40c3cc;
        if (_SigNum != 8) goto LAB_3b40c3ba;
      }
    }
    p_Var8 = __getptd_noexit();
    if (p_Var8 == (_ptiddata)0x0) {
      return -1;
    }
    uVar2 = _siglookup(extraout_ECX,_SigNum,(uint)p_Var8->_pxcptacttab);
    ppcVar7 = (code **)(uVar2 + 8);
    pcVar5 = *ppcVar7;
  }
  else {
    if (_SigNum == 0xf) {
      ppcVar7 = (code **)&DAT_3b417d88;
      uVar4 = DAT_3b417d88;
    }
    else if (_SigNum == 0x15) {
      ppcVar7 = (code **)&DAT_3b417d80;
      uVar4 = DAT_3b417d80;
    }
    else {
      if (_SigNum != 0x16) {
LAB_3b40c3ba:
        piVar3 = __errno();
        *piVar3 = 0x16;
        FUN_3b408343();
        return -1;
      }
LAB_3b40c3cc:
      ppcVar7 = (code **)&DAT_3b417d84;
      uVar4 = DAT_3b417d84;
    }
LAB_3b40c3ee:
    bVar1 = true;
    pcVar5 = (code *)(*(code *)PTR_FUN_3b416004)(uVar4);
  }
  if (pcVar5 == (code *)0x1) {
    return 0;
  }
  if (pcVar5 == (code *)0x0) {
                    // WARNING: Subroutine does not return
    __exit(3);
  }
  if (bVar1) {
    __lock(0);
  }
  if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
    local_30 = p_Var8->_tpxcptinfoptrs;
    p_Var8->_tpxcptinfoptrs = (void *)0x0;
    if (_SigNum == 8) {
      local_34 = p_Var8->_tfpecode;
      p_Var8->_tfpecode = 0x8c;
      goto LAB_3b40c452;
    }
  }
  else {
LAB_3b40c452:
    if (_SigNum == 8) {
      for (local_28 = 3; local_28 < 0xc; local_28 = local_28 + 1) {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var8->_pxcptacttab) = 0;
      }
      goto LAB_3b40c48a;
    }
  }
  pcVar6 = (code *)FUN_3b4071c6();
  *ppcVar7 = pcVar6;
LAB_3b40c48a:
  FUN_3b40c4ab();
  if (_SigNum == 8) {
    (*pcVar5)(8,p_Var8->_tfpecode);
  }
  else {
    (*pcVar5)(_SigNum);
    if ((_SigNum != 0xb) && (_SigNum != 4)) {
      return 0;
    }
  }
  p_Var8->_tpxcptinfoptrs = local_30;
  if (_SigNum == 8) {
    p_Var8->_tfpecode = local_34;
  }
  return 0;
}



void FUN_3b40c4ab(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_3b40aa8c(0);
  }
  return;
}



// Library Function - Single Match
//  ___crtMessageBoxW
// 
// Library: Visual Studio 2010 Release

int __cdecl ___crtMessageBoxW(LPCWSTR _LpText,LPCWSTR _LpCaption,UINT _UType)

{
  undefined *puVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  code *pcVar3;
  code *pcVar4;
  int iVar5;
  undefined local_28 [4];
  LPCWSTR local_24;
  LPCWSTR local_20;
  int local_1c;
  int local_18;
  undefined local_14 [8];
  byte local_c;
  uint local_8;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  local_24 = _LpText;
  local_20 = _LpCaption;
  local_1c = FUN_3b4071c6();
  local_18 = 0;
  if (DAT_3b417d90 == 0) {
    hModule = LoadLibraryW(L"USER32.DLL");
    if ((hModule == (HMODULE)0x0) ||
       (pFVar2 = GetProcAddress(hModule,"MessageBoxW"), puVar1 = PTR_FUN_3b416000,
       pFVar2 == (FARPROC)0x0)) goto LAB_3b40c644;
    DAT_3b417d90 = (*(code *)PTR_FUN_3b416000)(pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetActiveWindow");
    DAT_3b417d94 = (*(code *)puVar1)(pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetLastActivePopup");
    DAT_3b417d98 = (*(code *)puVar1)(pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetUserObjectInformationW");
    DAT_3b417da0 = (*(code *)puVar1)(pFVar2);
    if (DAT_3b417da0 != 0) {
      pFVar2 = GetProcAddress(hModule,"GetProcessWindowStation");
      DAT_3b417d9c = (*(code *)puVar1)(pFVar2);
    }
  }
  puVar1 = PTR_FUN_3b416004;
  if ((DAT_3b417d9c == local_1c) || (DAT_3b417da0 == local_1c)) {
LAB_3b40c5f3:
    if ((((DAT_3b417d94 != local_1c) &&
         (pcVar3 = (code *)(*(code *)puVar1)(DAT_3b417d94), pcVar3 != (code *)0x0)) &&
        (local_18 = (*pcVar3)(), local_18 != 0)) &&
       ((DAT_3b417d98 != local_1c &&
        (pcVar3 = (code *)(*(code *)puVar1)(DAT_3b417d98), pcVar3 != (code *)0x0)))) {
      local_18 = (*pcVar3)(local_18);
    }
  }
  else {
    pcVar3 = (code *)(*(code *)PTR_FUN_3b416004)(DAT_3b417d9c);
    pcVar4 = (code *)(*(code *)puVar1)(DAT_3b417da0);
    if (((pcVar3 == (code *)0x0) || (pcVar4 == (code *)0x0)) ||
       (((iVar5 = (*pcVar3)(), iVar5 != 0 &&
         (iVar5 = (*pcVar4)(iVar5,1,local_14,0xc,local_28), iVar5 != 0)) && ((local_c & 1) != 0))))
    goto LAB_3b40c5f3;
    _UType = _UType | 0x200000;
  }
  pcVar3 = (code *)(*(code *)puVar1)(DAT_3b417d90);
  if (pcVar3 != (code *)0x0) {
    (*pcVar3)(local_18,local_24,local_20,_UType);
  }
LAB_3b40c644:
  iVar5 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar5;
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  errno_t eStack_10;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        if (*pwVar3 == L'\0') break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        iVar4 = (int)pwVar3 - (int)_Src;
        do {
          wVar1 = *_Src;
          *(wchar_t *)(iVar4 + (int)_Src) = wVar1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        piVar2 = __errno();
        eStack_10 = 0x22;
        *piVar2 = 0x22;
        goto LAB_3b40c672;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_3b40c672:
  FUN_3b408343();
  return eStack_10;
}



// Library Function - Single Match
//  _wcsncpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  rsize_t rVar5;
  errno_t eStack_14;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords == 0) {
        return 0;
      }
    }
    else {
LAB_3b40c6ee:
      if (_SizeInWords != 0) {
        if (_MaxCount == 0) {
          *_Dst = L'\0';
          return 0;
        }
        if (_Src != (wchar_t *)0x0) {
          rVar5 = _SizeInWords;
          if (_MaxCount == 0xffffffff) {
            iVar4 = (int)_Dst - (int)_Src;
            do {
              wVar1 = *_Src;
              *(wchar_t *)(iVar4 + (int)_Src) = wVar1;
              _Src = _Src + 1;
              if (wVar1 == L'\0') break;
              rVar5 = rVar5 - 1;
            } while (rVar5 != 0);
          }
          else {
            pwVar3 = _Dst;
            do {
              wVar1 = *(wchar_t *)(((int)_Src - (int)_Dst) + (int)pwVar3);
              *pwVar3 = wVar1;
              pwVar3 = pwVar3 + 1;
              if ((wVar1 == L'\0') || (rVar5 = rVar5 - 1, rVar5 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pwVar3 = L'\0';
            }
          }
          if (rVar5 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffff) {
            _Dst[_SizeInWords - 1] = L'\0';
            return 0x50;
          }
          *_Dst = L'\0';
          piVar2 = __errno();
          eStack_14 = 0x22;
          *piVar2 = 0x22;
          goto LAB_3b40c6ff;
        }
        *_Dst = L'\0';
      }
    }
  }
  else if (_Dst != (wchar_t *)0x0) goto LAB_3b40c6ee;
  piVar2 = __errno();
  eStack_14 = 0x16;
  *piVar2 = 0x16;
LAB_3b40c6ff:
  FUN_3b408343();
  return eStack_14;
}



// Library Function - Single Match
//  _wcslen
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2015 Release,
// Visual Studio 2019 Release

size_t __cdecl _wcslen(wchar_t *_Str)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Str;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  return ((int)pwVar2 - (int)_Str >> 1) - 1;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  int iVar3;
  errno_t eStack_10;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    if (_Src != (wchar_t *)0x0) {
      iVar3 = (int)_Dst - (int)_Src;
      do {
        wVar1 = *_Src;
        *(wchar_t *)(iVar3 + (int)_Src) = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      piVar2 = __errno();
      eStack_10 = 0x22;
      *piVar2 = 0x22;
      goto LAB_3b40c7cf;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_3b40c7cf:
  FUN_3b408343();
  return eStack_10;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2010 Release

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  int *piVar2;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar1 = DAT_3b417428;
      DAT_3b417428 = _Mode;
      return iVar1;
    }
    if (_Mode == 3) {
      return DAT_3b417428;
    }
  }
  piVar2 = __errno();
  *piVar2 = 0x16;
  FUN_3b408343();
  return -1;
}



// Library Function - Single Match
//  __freea
// 
// Library: Visual Studio 2010 Release

void __cdecl __freea(void *_Memory)

{
  if ((_Memory != (void *)0x0) && (*(int *)((int)_Memory + -8) == 0xdddd)) {
    _free((int *)((int)_Memory + -8));
  }
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1
// Library Function - Single Match
//  __EH_prolog3_catch
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __cdecl __EH_prolog3_catch(int param_1)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  int *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = securityCookie ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
  return;
}



// Library Function - Single Match
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 2010 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  return (uint)(param_1 != (void *)0x0);
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar1 = (undefined4 *)((_Size - 4) + (int)_Src);
    puVar4 = (undefined4 *)((_Size - 4) + (int)_Dst);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = _Size >> 2;
      uVar3 = _Size & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return _Dst;
        case 2:
          goto switchD_3b40ca9f_caseD_2;
        case 3:
          goto switchD_3b40ca9f_caseD_3;
        }
        goto switchD_3b40ca9f_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_3b40ca9f_caseD_0;
      case 1:
        goto switchD_3b40ca9f_caseD_1;
      case 2:
        goto switchD_3b40ca9f_caseD_2;
      case 3:
        goto switchD_3b40ca9f_caseD_3;
      default:
        uVar2 = _Size - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          puVar1 = (undefined4 *)((int)puVar1 + -1);
          uVar2 = uVar2 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_3b40ca9f_caseD_2;
            case 3:
              goto switchD_3b40ca9f_caseD_3;
            }
            goto switchD_3b40ca9f_caseD_1;
          }
          break;
        case 2:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          puVar1 = (undefined4 *)((int)puVar1 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_3b40ca9f_caseD_2;
            case 3:
              goto switchD_3b40ca9f_caseD_3;
            }
            goto switchD_3b40ca9f_caseD_1;
          }
          break;
        case 3:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
          puVar1 = (undefined4 *)((int)puVar1 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_3b40ca9f_caseD_2;
            case 3:
              goto switchD_3b40ca9f_caseD_3;
            }
            goto switchD_3b40ca9f_caseD_1;
          }
        }
      }
    }
    switch(uVar2) {
    case 7:
      puVar4[7 - uVar2] = puVar1[7 - uVar2];
    case 6:
      puVar4[6 - uVar2] = puVar1[6 - uVar2];
    case 5:
      puVar4[5 - uVar2] = puVar1[5 - uVar2];
    case 4:
      puVar4[4 - uVar2] = puVar1[4 - uVar2];
    case 3:
      puVar4[3 - uVar2] = puVar1[3 - uVar2];
    case 2:
      puVar4[2 - uVar2] = puVar1[2 - uVar2];
    case 1:
      puVar4[1 - uVar2] = puVar1[1 - uVar2];
      puVar1 = puVar1 + -uVar2;
      puVar4 = puVar4 + -uVar2;
    }
    switch(uVar3) {
    case 1:
switchD_3b40ca9f_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_3b40ca9f_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_3b40ca9f_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_3b40ca9f_caseD_0:
    return _Dst;
  }
  if (((0x7f < _Size) && (DAT_3b4180e8 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
    puVar1 = __VEC_memcpy(_Size);
    return puVar1;
  }
  puVar1 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
    uVar2 = _Size >> 2;
    uVar3 = _Size & 3;
    if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *_Src;
        _Src = (undefined4 *)((int)_Src + 4);
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return _Dst;
      case 2:
        goto switchD_3b40c919_caseD_2;
      case 3:
        goto switchD_3b40c919_caseD_3;
      }
      goto switchD_3b40c919_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_3b40c919_caseD_0;
    case 1:
      goto switchD_3b40c919_caseD_1;
    case 2:
      goto switchD_3b40c919_caseD_2;
    case 3:
      goto switchD_3b40c919_caseD_3;
    default:
      uVar2 = (_Size - 4) + ((uint)_Dst & 3);
      switch((uint)_Dst & 3) {
      case 1:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 2) = *(undefined *)((int)_Src + 2);
        _Src = (void *)((int)_Src + 3);
        puVar1 = (undefined4 *)((int)_Dst + 3);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_3b40c919_caseD_2;
          case 3:
            goto switchD_3b40c919_caseD_3;
          }
          goto switchD_3b40c919_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        _Src = (void *)((int)_Src + 2);
        puVar1 = (undefined4 *)((int)_Dst + 2);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_3b40c919_caseD_2;
          case 3:
            goto switchD_3b40c919_caseD_3;
          }
          goto switchD_3b40c919_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        _Src = (void *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)_Dst + 1);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_3b40c919_caseD_2;
          case 3:
            goto switchD_3b40c919_caseD_3;
          }
          goto switchD_3b40c919_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar2) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 7] = *(undefined4 *)((int)_Src + (uVar2 - 7) * 4);
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = *(undefined4 *)((int)_Src + (uVar2 - 6) * 4);
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = *(undefined4 *)((int)_Src + (uVar2 - 5) * 4);
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = *(undefined4 *)((int)_Src + (uVar2 - 4) * 4);
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = *(undefined4 *)((int)_Src + (uVar2 - 3) * 4);
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = *(undefined4 *)((int)_Src + (uVar2 - 2) * 4);
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = *(undefined4 *)((int)_Src + (uVar2 - 1) * 4);
    _Src = (void *)((int)_Src + uVar2 * 4);
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_3b40c919_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_3b40c919_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_3b40c919_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_3b40c919_caseD_0:
  return _Dst;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___report_gsfailure(void)

{
  undefined4 in_EAX;
  HANDLE hProcess;
  undefined4 in_ECX;
  undefined4 in_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 unaff_retaddr;
  UINT uExitCode;
  undefined4 local_32c;
  undefined4 local_328;
  
  _DAT_3b417ec0 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_3b417ec4 = &stack0x00000004;
  _DAT_3b417e00 = 0x10001;
  _DAT_3b417da8 = 0xc0000409;
  _DAT_3b417dac = 1;
  local_32c = securityCookie;
  local_328 = invertedSecurityCookie;
  _DAT_3b417db4 = unaff_retaddr;
  _DAT_3b417e8c = in_GS;
  _DAT_3b417e90 = in_FS;
  _DAT_3b417e94 = in_ES;
  _DAT_3b417e98 = in_DS;
  _DAT_3b417e9c = unaff_EDI;
  _DAT_3b417ea0 = unaff_ESI;
  _DAT_3b417ea4 = unaff_EBX;
  _DAT_3b417ea8 = in_EDX;
  _DAT_3b417eac = in_ECX;
  _DAT_3b417eb0 = in_EAX;
  _DAT_3b417eb4 = unaff_EBP;
  DAT_3b417eb8 = unaff_retaddr;
  _DAT_3b417ebc = in_CS;
  _DAT_3b417ec8 = in_SS;
  DAT_3b417df8 = IsDebuggerPresent();
  FUN_3b40de02();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&ExceptionInfo_3b413148);
  if (DAT_3b417df8 == 0) {
    FUN_3b40de02();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x3b40cd48,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind2(int param_1,uint param_2)

{
  uint uVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_20;
  undefined *puStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  puStack_1c = &LAB_3b40cd50;
  local_20 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_3b40ce64();
    }
  }
  *unaff_FS_OFFSET = local_20;
  return;
}



// Library Function - Single Match
//  __NLG_Notify1
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

undefined4 __fastcall __NLG_Notify1(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_3b416eb8 = param_1;
  DAT_3b416eb4 = in_EAX;
  DAT_3b416ebc = unaff_EBP;
  return in_EAX;
}



// Library Function - Single Match
//  __NLG_Notify
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __NLG_Notify(ulong param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_3b416eb8 = param_1;
  DAT_3b416eb4 = in_EAX;
  DAT_3b416ebc = unaff_EBP;
  return;
}



void FUN_3b40ce64(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_3b40ce67(undefined4 param_1)

{
  _DAT_3b4180cc = param_1;
  return;
}



// Library Function - Single Match
//  __initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2010 Release

void __initp_misc_cfltcvt_tab(void)

{
  undefined4 uVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    uVar1 = (*(code *)PTR_FUN_3b416000)(*(undefined4 *)((int)&PTR_LAB_3b416ec0 + uVar2));
    *(undefined4 *)((int)&PTR_LAB_3b416ec0 + uVar2) = uVar1;
    uVar2 = uVar2 + 4;
  } while (uVar2 < 0x28);
  return;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return 0;
}



// Library Function - Single Match
//  __FindPESection
// 
// Library: Visual Studio 2010 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  uVar3 = 0;
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2010 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  uint uVar1;
  BOOL BVar2;
  PIMAGE_SECTION_HEADER p_Var3;
  int **unaff_FS_OFFSET;
  int *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = __except_handler4;
  local_14 = *unaff_FS_OFFSET;
  local_c = securityCookie ^ 0x3b4143f8;
  *unaff_FS_OFFSET = (int *)&local_14;
  local_8 = 0;
  BVar2 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_3b400000);
  if (BVar2 != 0) {
    p_Var3 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_3b400000,(DWORD_PTR)(pTarget + -0x3b400000));
    if (p_Var3 != (PIMAGE_SECTION_HEADER)0x0) {
      uVar1 = p_Var3->Characteristics;
      *unaff_FS_OFFSET = local_14;
      return ~(uVar1 >> 0x1f) & 1;
    }
  }
  *unaff_FS_OFFSET = local_14;
  return 0;
}



// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2010 Release

LPVOID __cdecl __calloc_impl(uint param_1,uint param_2,undefined4 *param_3)

{
  int *piVar1;
  LPVOID pvVar2;
  int iVar3;
  uint dwBytes;
  
  if ((param_1 != 0) && (0xffffffe0 / param_1 < param_2)) {
    piVar1 = __errno();
    *piVar1 = 0xc;
    return (LPVOID)0x0;
  }
  dwBytes = param_1 * param_2;
  if (dwBytes == 0) {
    dwBytes = 1;
  }
  do {
    pvVar2 = (LPVOID)0x0;
    if ((dwBytes < 0xffffffe1) &&
       (pvVar2 = HeapAlloc(hHeap_3b417a7c,8,dwBytes), pvVar2 != (LPVOID)0x0)) {
      return pvVar2;
    }
    if (DAT_3b417ab4 == 0) {
      if (param_3 == (undefined4 *)0x0) {
        return pvVar2;
      }
      *param_3 = 0xc;
      return pvVar2;
    }
    iVar3 = __callnewh(dwBytes);
  } while (iVar3 != 0);
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = 0xc;
  }
  return (LPVOID)0x0;
}



// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl _realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  LPVOID pvVar2;
  int iVar3;
  int *piVar4;
  DWORD DVar5;
  
  if (_Memory == (void *)0x0) {
    pvVar1 = _malloc(_NewSize);
    return pvVar1;
  }
  if (_NewSize == 0) {
    _free(_Memory);
  }
  else {
    do {
      if (0xffffffe0 < _NewSize) {
        __callnewh(_NewSize);
        piVar4 = __errno();
        *piVar4 = 0xc;
        return (void *)0x0;
      }
      if (_NewSize == 0) {
        _NewSize = 1;
      }
      pvVar2 = HeapReAlloc(hHeap_3b417a7c,0,_Memory,_NewSize);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (DAT_3b417ab4 == 0) {
        piVar4 = __errno();
        DVar5 = GetLastError();
        iVar3 = __get_errno_from_oserr(DVar5);
        *piVar4 = iVar3;
        return (void *)0x0;
      }
      iVar3 = __callnewh(_NewSize);
    } while (iVar3 != 0);
    piVar4 = __errno();
    DVar5 = GetLastError();
    iVar3 = __get_errno_from_oserr(DVar5);
    *piVar4 = iVar3;
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __recalloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl __recalloc(void *_Memory,size_t _Count,size_t _Size)

{
  int *piVar1;
  void *pvVar2;
  uint _NewSize;
  size_t sVar3;
  
  sVar3 = 0;
  if ((_Count == 0) || (_Size <= 0xffffffe0 / _Count)) {
    _NewSize = _Count * _Size;
    if (_Memory != (void *)0x0) {
      sVar3 = __msize(_Memory);
    }
    pvVar2 = _realloc(_Memory,_NewSize);
    if ((pvVar2 != (void *)0x0) && (sVar3 < _NewSize)) {
      _memset((void *)(sVar3 + (int)pvVar2),0,_NewSize - sVar3);
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0xc;
    pvVar2 = (void *)0x0;
  }
  return pvVar2;
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 2010 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < uNumber_3b4180ec)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_3b418100)[param_1 >> 5]) == -1) {
      if (DAT_3b41742c == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_3b40d1e6;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_3b40d1e6:
      *(intptr_t *)(iVar3 + (&DAT_3b418100)[param_1 >> 5]) = param_2;
      return 0;
    }
  }
  piVar1 = __errno();
  *piVar1 = 9;
  puVar2 = ___doserrno();
  *puVar2 = 0;
  return -1;
}



// Library Function - Single Match
//  __free_osfhnd
// 
// Library: Visual Studio 2010 Release

int __cdecl __free_osfhnd(int param_1)

{
  int iVar1;
  int *piVar2;
  ulong *puVar3;
  int iVar4;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < uNumber_3b4180ec)) {
    iVar1 = (&DAT_3b418100)[param_1 >> 5];
    iVar4 = (param_1 & 0x1fU) * 0x40;
    if (((*(byte *)(iVar1 + 4 + iVar4) & 1) != 0) && (*(int *)(iVar1 + iVar4) != -1)) {
      if (DAT_3b41742c == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_3b40d26c;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_3b40d26c:
      *(undefined4 *)(iVar4 + (&DAT_3b418100)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  piVar2 = __errno();
  *piVar2 = 9;
  puVar3 = ___doserrno();
  *puVar3 = 0;
  return -1;
}



// Library Function - Single Match
//  __get_osfhandle
// 
// Library: Visual Studio 2010 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar3 + 4 + (&DAT_3b418100)[_FileHandle >> 5]) & 1) != 0) {
        return *(intptr_t *)(iVar3 + (&DAT_3b418100)[_FileHandle >> 5]);
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_3b408343();
  }
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___lock_fhandle
// 
// Library: Visual Studio 2010 Release

int __cdecl ___lock_fhandle(int _Filehandle)

{
  BOOL BVar1;
  int iVar2;
  uint local_20;
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_3b418100)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_3b40d38f();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_3b418100)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_3b40d38f(void)

{
  FUN_3b40aa8c(10);
  return;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Library: Visual Studio 2010 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_3b418100)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __alloc_osfhnd
// 
// Library: Visual Studio 2010 Release

int __cdecl __alloc_osfhnd(void)

{
  bool bVar1;
  int iVar2;
  BOOL BVar3;
  undefined4 *puVar4;
  int iVar5;
  int local_20;
  
  local_20 = -1;
  iVar5 = 0;
  bVar1 = false;
  iVar2 = __mtinitlocknum(0xb);
  if (iVar2 == 0) {
    local_20 = -1;
  }
  else {
    __lock(0xb);
    for (; iVar5 < 0x40; iVar5 = iVar5 + 1) {
      puVar4 = (undefined4 *)(&DAT_3b418100)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_3b418100)[iVar5] = puVar4;
          uNumber_3b4180ec = uNumber_3b4180ec + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_3b418100)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_3b418100)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_3b418100)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
        if ((*(byte *)(puVar4 + 1) & 1) == 0) {
          if (puVar4[2] == 0) {
            __lock(10);
            if (puVar4[2] == 0) {
              BVar3 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(puVar4 + 3),4000);
              if (BVar3 == 0) {
                bVar1 = true;
              }
              else {
                puVar4[2] = puVar4[2] + 1;
              }
            }
            FUN_3b40d491();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_3b418100)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_3b40d54f();
  }
  return local_20;
}



void FUN_3b40d491(void)

{
  FUN_3b40aa8c(10);
  return;
}



void FUN_3b40d54f(void)

{
  FUN_3b40aa8c(0xb);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  char cVar1;
  WCHAR WVar2;
  wchar_t *pwVar3;
  wint_t wVar4;
  ulong *puVar5;
  int *piVar6;
  int iVar7;
  _ptiddata p_Var8;
  BOOL BVar9;
  DWORD nNumberOfBytesToWrite;
  WCHAR *pWVar10;
  int iVar11;
  uint uVar12;
  WCHAR *pWVar13;
  uint uVar14;
  int iVar15;
  size_t _SrcSizeInBytes;
  uint local_1ae8;
  WCHAR *local_1ae4;
  int *local_1ae0;
  uint local_1adc;
  WCHAR *local_1ad8;
  int local_1ad4;
  WCHAR *local_1ad0;
  uint local_1acc;
  char local_1ac5;
  uint local_1ac4;
  DWORD local_1ac0;
  WCHAR local_1abc [852];
  CHAR local_1414 [3416];
  WCHAR local_6bc [854];
  undefined local_10;
  char local_f;
  uint local_8;
  
  local_8 = securityCookie ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = 0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_3b40dc47;
  if (_Buf == (void *)0x0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_3b408343();
    goto LAB_3b40dc47;
  }
  piVar6 = &DAT_3b418100 + (_FileHandle >> 5);
  iVar11 = (_FileHandle & 0x1fU) * 0x40;
  local_1ac5 = (char)(*(char *)(*piVar6 + 0x24 + iVar11) * '\x02') >> 1;
  local_1ae0 = piVar6;
  if (((local_1ac5 == '\x02') || (local_1ac5 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_3b408343();
    goto LAB_3b40dc47;
  }
  if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0,2);
  }
  iVar7 = __isatty(_FileHandle);
  if ((iVar7 == 0) || ((*(byte *)(iVar11 + 4 + *piVar6) & 0x80) == 0)) {
LAB_3b40d8d8:
    if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x80) == 0) {
      BVar9 = WriteFile(*(HANDLE *)(*piVar6 + iVar11),local_1ad0,_MaxCharCount,&local_1adc,
                        (LPOVERLAPPED)0x0);
      if (BVar9 == 0) {
LAB_3b40dbb9:
        local_1ac0 = GetLastError();
      }
      else {
        local_1ac0 = 0;
        local_1acc = local_1adc;
      }
LAB_3b40dbc5:
      if (local_1acc != 0) goto LAB_3b40dc47;
      goto LAB_3b40dbce;
    }
    local_1ac0 = 0;
    if (local_1ac5 == '\0') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_3b40dc04;
      do {
        uVar14 = 0;
        uVar12 = (int)pWVar13 - (int)local_1ad0;
        pWVar10 = local_1abc;
        do {
          if (_MaxCharCount <= uVar12) break;
          cVar1 = *(char *)pWVar13;
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          uVar12 = uVar12 + 1;
          if (cVar1 == '\n') {
            local_1ad4 = local_1ad4 + 1;
            *(char *)pWVar10 = '\r';
            pWVar10 = (WCHAR *)((int)pWVar10 + 1);
            uVar14 = uVar14 + 1;
          }
          *(char *)pWVar10 = cVar1;
          pWVar10 = (WCHAR *)((int)pWVar10 + 1);
          uVar14 = uVar14 + 1;
          local_1ae4 = pWVar13;
        } while (uVar14 < 0x13ff);
        BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1abc,
                          (int)pWVar10 - (int)local_1abc,&local_1adc,(LPOVERLAPPED)0x0);
        if (BVar9 == 0) goto LAB_3b40dbb9;
        local_1acc = local_1acc + local_1adc;
      } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
              ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_3b40dbc5;
    }
    if (local_1ac5 == '\x02') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac4 = 0;
          uVar12 = (int)pWVar13 - (int)local_1ad0;
          pWVar10 = local_1abc;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar2 = *pWVar13;
            pWVar13 = pWVar13 + 1;
            uVar12 = uVar12 + 2;
            if (WVar2 == L'\n') {
              local_1ad4 = local_1ad4 + 2;
              *pWVar10 = L'\r';
              pWVar10 = pWVar10 + 1;
              local_1ac4 = local_1ac4 + 2;
            }
            local_1ac4 = local_1ac4 + 2;
            *pWVar10 = WVar2;
            pWVar10 = pWVar10 + 1;
            local_1ae4 = pWVar13;
          } while (local_1ac4 < 0x13fe);
          BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1abc,
                            (int)pWVar10 - (int)local_1abc,&local_1adc,(LPOVERLAPPED)0x0);
          if (BVar9 == 0) goto LAB_3b40dbb9;
          local_1acc = local_1acc + local_1adc;
        } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
                ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_3b40dbc5;
      }
    }
    else {
      local_1ad8 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac4 = 0;
          uVar12 = (int)local_1ad8 - (int)local_1ad0;
          pWVar13 = local_6bc;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar2 = *local_1ad8;
            local_1ad8 = local_1ad8 + 1;
            uVar12 = uVar12 + 2;
            if (WVar2 == L'\n') {
              *pWVar13 = L'\r';
              pWVar13 = pWVar13 + 1;
              local_1ac4 = local_1ac4 + 2;
            }
            local_1ac4 = local_1ac4 + 2;
            *pWVar13 = WVar2;
            pWVar13 = pWVar13 + 1;
          } while (local_1ac4 < 0x6a8);
          iVar15 = 0;
          iVar7 = WideCharToMultiByte(0xfde9,0,local_6bc,((int)pWVar13 - (int)local_6bc) / 2,
                                      local_1414,0xd55,(LPCSTR)0x0,(LPBOOL)0x0);
          if (iVar7 == 0) goto LAB_3b40dbb9;
          do {
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1414 + iVar15,iVar7 - iVar15,
                              &local_1adc,(LPOVERLAPPED)0x0);
            if (BVar9 == 0) {
              local_1ac0 = GetLastError();
              break;
            }
            iVar15 = iVar15 + local_1adc;
          } while (iVar15 < iVar7);
        } while ((iVar7 <= iVar15) &&
                (local_1acc = (int)local_1ad8 - (int)local_1ad0, local_1acc < _MaxCharCount));
        goto LAB_3b40dbc5;
      }
    }
  }
  else {
    p_Var8 = __getptd();
    pwVar3 = p_Var8->ptlocinfo->lc_category[0].wlocale;
    BVar9 = GetConsoleMode(*(HANDLE *)(iVar11 + *piVar6),(LPDWORD)&local_1ae4);
    if ((BVar9 == 0) || ((pwVar3 == (wchar_t *)0x0 && (local_1ac5 == '\0')))) goto LAB_3b40d8d8;
    local_1ae4 = (WCHAR *)GetConsoleCP();
    local_1ad8 = (WCHAR *)0x0;
    if (_MaxCharCount != 0) {
      local_1ac4 = 0;
      pWVar13 = local_1ad0;
      do {
        piVar6 = local_1ae0;
        if (local_1ac5 == '\0') {
          cVar1 = *(char *)pWVar13;
          local_1ae8 = (uint)(cVar1 == '\n');
          iVar7 = *local_1ae0 + iVar11;
          if (*(int *)(iVar7 + 0x38) == 0) {
            iVar7 = _isleadbyte((int)cVar1);
            if (iVar7 == 0) {
              _SrcSizeInBytes = 1;
              pWVar10 = pWVar13;
              goto LAB_3b40d73f;
            }
            if ((char *)((int)local_1ad0 + (_MaxCharCount - (int)pWVar13)) < (char *)0x2) {
              local_1acc = local_1acc + 1;
              *(undefined *)(iVar11 + 0x34 + *piVar6) = *(undefined *)pWVar13;
              *(undefined4 *)(iVar11 + 0x38 + *piVar6) = 1;
              break;
            }
            iVar7 = _mbtowc((wchar_t *)&local_1ac0,(char *)pWVar13,2);
            if (iVar7 == -1) break;
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_1ac4 = local_1ac4 + 1;
          }
          else {
            local_10 = *(undefined *)(iVar7 + 0x34);
            *(undefined4 *)(iVar7 + 0x38) = 0;
            _SrcSizeInBytes = 2;
            pWVar10 = (WCHAR *)&local_10;
            local_f = cVar1;
LAB_3b40d73f:
            iVar7 = _mbtowc((wchar_t *)&local_1ac0,(char *)pWVar10,_SrcSizeInBytes);
            if (iVar7 == -1) break;
          }
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          local_1ac4 = local_1ac4 + 1;
          nNumberOfBytesToWrite =
               WideCharToMultiByte((UINT)local_1ae4,0,(LPCWSTR)&local_1ac0,1,&local_10,5,(LPCSTR)0x0
                                   ,(LPBOOL)0x0);
          if (nNumberOfBytesToWrite == 0) break;
          BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,nNumberOfBytesToWrite,
                            (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar9 == 0) goto LAB_3b40dbb9;
          local_1acc = local_1ac4 + local_1ad4;
          if ((int)local_1ad8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae8 != 0) {
            local_10 = 0xd;
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,1,(LPDWORD)&local_1ad8,
                              (LPOVERLAPPED)0x0);
            if (BVar9 == 0) goto LAB_3b40dbb9;
            if ((int)local_1ad8 < 1) break;
            local_1ad4 = local_1ad4 + 1;
            local_1acc = local_1acc + 1;
          }
        }
        else {
          if ((local_1ac5 == '\x01') || (local_1ac5 == '\x02')) {
            local_1ac0 = (DWORD)(ushort)*pWVar13;
            local_1ae8 = (uint)(local_1ac0 == 10);
            pWVar13 = pWVar13 + 1;
            local_1ac4 = local_1ac4 + 2;
          }
          if ((local_1ac5 == '\x01') || (local_1ac5 == '\x02')) {
            wVar4 = __putwch_nolock((wchar_t)local_1ac0);
            if (wVar4 != (wint_t)local_1ac0) goto LAB_3b40dbb9;
            local_1acc = local_1acc + 2;
            if (local_1ae8 != 0) {
              local_1ac0 = 0xd;
              wVar4 = __putwch_nolock(L'\r');
              if (wVar4 != (wint_t)local_1ac0) goto LAB_3b40dbb9;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac4 < _MaxCharCount);
      goto LAB_3b40dbc5;
    }
LAB_3b40dbce:
    if (local_1ac0 != 0) {
      if (local_1ac0 == 5) {
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        __dosmaperr(local_1ac0);
      }
      goto LAB_3b40dc47;
    }
  }
LAB_3b40dc04:
  if (((*(byte *)(iVar11 + 4 + *local_1ae0) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar6 = __errno();
    *piVar6 = 0x1c;
    puVar5 = ___doserrno();
    *puVar5 = 0;
  }
LAB_3b40dc47:
  iVar11 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar11;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2010 Release

int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_3b40dd21();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_3b408343();
  }
  return -1;
}



void FUN_3b40dd21(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2010 Release

int __cdecl __commit(int _FileHandle)

{
  int *piVar1;
  HANDLE hFile;
  BOOL BVar2;
  ulong *puVar3;
  int iVar4;
  DWORD local_20;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_3b418100)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_3b418100)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_3b40dde2;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_3b40dde2:
        FUN_3b40ddfa();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_3b408343();
  }
  return -1;
}



void FUN_3b40ddfa(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_3b40de02(void)

{
  _DAT_3b4180e4 = 0;
  return;
}



// Library Function - Single Match
//  __isctype_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  BOOL BVar2;
  CHAR CVar3;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  CHAR local_c;
  CHAR local_b;
  undefined local_a;
  ushort local_8 [2];
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if (_C + 1U < 0x101) {
    local_8[0] = *(ushort *)(local_1c.locinfo[1].lc_category[0].locale + _C * 2);
  }
  else {
    iVar1 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c);
    CVar3 = (CHAR)_C;
    if (iVar1 == 0) {
      local_b = '\0';
      iVar1 = 1;
      local_c = CVar3;
    }
    else {
      _C._0_1_ = (CHAR)((uint)_C >> 8);
      local_c = (CHAR)_C;
      local_a = 0;
      iVar1 = 2;
      local_b = CVar3;
    }
    BVar2 = ___crtGetStringTypeA
                      (&local_1c,1,&local_c,iVar1,local_8,(local_1c.locinfo)->lc_codepage,
                       (BOOL)(local_1c.locinfo)->lc_category[0].wlocale);
    if (BVar2 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return (uint)local_8[0] & _Type;
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio 2010 Release

longlong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



// Library Function - Single Match
//  __aulldvrm
// 
// Library: Visual Studio

undefined8 __aulldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

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
//  __read_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __read_nolock(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  byte *pbVar1;
  uint uVar2;
  byte bVar3;
  char cVar4;
  ulong *puVar5;
  int *piVar6;
  uint uVar7;
  short *psVar8;
  BOOL BVar9;
  DWORD DVar10;
  ulong uVar11;
  short *psVar12;
  int iVar13;
  int iVar14;
  bool bVar15;
  longlong lVar16;
  short sVar17;
  uint local_1c;
  int local_18;
  short *local_14;
  short *local_10;
  undefined2 local_c;
  char local_6;
  char local_5;
  
  uVar2 = _MaxCharCount;
  local_18 = -2;
  if (_FileHandle == -2) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    return -1;
  }
  if ((_FileHandle < 0) || (uNumber_3b4180ec <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    FUN_3b408343();
    return -1;
  }
  piVar6 = &DAT_3b418100 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + 4 + iVar14);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_3b40e0a4;
  }
  if (_MaxCharCount < 0x80000000) {
    local_10 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + 0x24 + iVar14) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_3b40e092;
        uVar7 = _MaxCharCount >> 1;
        _MaxCharCount = 4;
        if (3 < uVar7) {
          _MaxCharCount = uVar7;
        }
        psVar12 = (short *)__malloc_crt(_MaxCharCount);
        local_14 = psVar12;
        if (psVar12 == (short *)0x0) {
          piVar6 = __errno();
          *piVar6 = 0xc;
          puVar5 = ___doserrno();
          *puVar5 = 8;
          return -1;
        }
        lVar16 = __lseeki64_nolock(_FileHandle,0,1);
        iVar13 = *piVar6;
        *(int *)(iVar14 + 0x28 + iVar13) = (int)lVar16;
        *(int *)(iVar14 + 0x2c + iVar13) = (int)((ulonglong)lVar16 >> 0x20);
      }
      else {
        if (local_6 == '\x02') {
          if ((~_MaxCharCount & 1) == 0) goto LAB_3b40e092;
          _MaxCharCount = _MaxCharCount & 0xfffffffe;
        }
        local_14 = (short *)_DstBuf;
        psVar12 = (short *)_DstBuf;
      }
      psVar8 = psVar12;
      uVar7 = _MaxCharCount;
      if ((((*(byte *)(*piVar6 + iVar14 + 4) & 0x48) != 0) &&
          (cVar4 = *(char *)(*piVar6 + iVar14 + 5), cVar4 != '\n')) && (_MaxCharCount != 0)) {
        uVar7 = _MaxCharCount - 1;
        *(char *)psVar12 = cVar4;
        psVar8 = (short *)((int)psVar12 + 1);
        local_10 = (short *)0x1;
        *(undefined *)(iVar14 + 5 + *piVar6) = 10;
        if (((local_6 != '\0') && (cVar4 = *(char *)(iVar14 + 0x25 + *piVar6), cVar4 != '\n')) &&
           (uVar7 != 0)) {
          *(char *)psVar8 = cVar4;
          psVar8 = psVar12 + 1;
          uVar7 = _MaxCharCount - 2;
          local_10 = (short *)0x2;
          *(undefined *)(iVar14 + 0x25 + *piVar6) = 10;
          if (((local_6 == '\x01') && (cVar4 = *(char *)(iVar14 + 0x26 + *piVar6), cVar4 != '\n'))
             && (uVar7 != 0)) {
            *(char *)psVar8 = cVar4;
            psVar8 = (short *)((int)psVar12 + 3);
            local_10 = (short *)0x3;
            *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
            uVar7 = _MaxCharCount - 3;
          }
        }
      }
      _MaxCharCount = uVar7;
      BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),psVar8,_MaxCharCount,&local_1c,
                       (LPOVERLAPPED)0x0);
      if (((BVar9 == 0) || ((int)local_1c < 0)) || (_MaxCharCount < local_1c)) {
        uVar11 = GetLastError();
        if (uVar11 != 5) {
          if (uVar11 == 0x6d) {
            local_18 = 0;
            goto LAB_3b40e3b1;
          }
          goto LAB_3b40e3a6;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_10 = (short *)((int)local_10 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_3b40e3b1;
        if (local_6 == '\x02') {
          if ((local_1c == 0) || (*psVar12 != 10)) {
            *pbVar1 = *pbVar1 & 0xfb;
          }
          else {
            *pbVar1 = *pbVar1 | 4;
          }
          local_10 = (short *)((int)local_10 + (int)local_14);
          _MaxCharCount = (uint)local_14;
          psVar12 = local_14;
          if (local_14 < local_10) {
            do {
              sVar17 = *(short *)_MaxCharCount;
              if (sVar17 == 0x1a) {
                pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
                if ((*pbVar1 & 0x40) == 0) {
                  *pbVar1 = *pbVar1 | 2;
                }
                else {
                  *psVar12 = *(short *)_MaxCharCount;
                  psVar12 = psVar12 + 1;
                }
                break;
              }
              if (sVar17 == 0xd) {
                if (_MaxCharCount < local_10 + -1) {
                  if (*(short *)(_MaxCharCount + 2) == 10) {
                    uVar2 = _MaxCharCount + 4;
                    goto LAB_3b40e451;
                  }
LAB_3b40e4e4:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_3b40e4e6:
                  *psVar12 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_3b40e4e4;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar12 == local_14) && (local_c == 10)) goto LAB_3b40e451;
                    __lseeki64_nolock(_FileHandle,-2,1);
                    if (local_c == 10) goto LAB_3b40e4ed;
                    goto LAB_3b40e4e4;
                  }
                  if (local_c == 10) {
LAB_3b40e451:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_3b40e4e6;
                  }
                  *psVar12 = 0xd;
                  *(undefined *)(iVar14 + 5 + *piVar6) = (undefined)local_c;
                  *(undefined *)(iVar14 + 0x25 + *piVar6) = local_c._1_1_;
                  *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
                  _MaxCharCount = uVar2;
                }
                psVar12 = psVar12 + 1;
                uVar2 = _MaxCharCount;
              }
              else {
                *psVar12 = sVar17;
                psVar12 = psVar12 + 1;
                uVar2 = _MaxCharCount + 2;
              }
LAB_3b40e4ed:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_10);
          }
          local_10 = (short *)((int)psVar12 - (int)local_14);
          goto LAB_3b40e3b1;
        }
        if ((local_1c == 0) || (*(char *)psVar12 != '\n')) {
          *pbVar1 = *pbVar1 & 0xfb;
        }
        else {
          *pbVar1 = *pbVar1 | 4;
        }
        local_10 = (short *)((int)local_10 + (int)local_14);
        _MaxCharCount = (uint)local_14;
        psVar12 = local_14;
        if (local_14 < local_10) {
          do {
            cVar4 = *(char *)_MaxCharCount;
            if (cVar4 == '\x1a') {
              pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
              if ((*pbVar1 & 0x40) == 0) {
                *pbVar1 = *pbVar1 | 2;
              }
              else {
                *(undefined *)psVar12 = *(undefined *)_MaxCharCount;
                psVar12 = (short *)((int)psVar12 + 1);
              }
              break;
            }
            if (cVar4 == '\r') {
              if (_MaxCharCount < (undefined *)((int)local_10 + -1)) {
                if (*(char *)(_MaxCharCount + 1) == '\n') {
                  uVar7 = _MaxCharCount + 2;
                  goto LAB_3b40e231;
                }
LAB_3b40e2a8:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar12 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_3b40e2a8;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar12 == local_14) && (local_5 == '\n')) goto LAB_3b40e231;
                  __lseeki64_nolock(_FileHandle,-1,1);
                  if (local_5 == '\n') goto LAB_3b40e2ac;
                  goto LAB_3b40e2a8;
                }
                if (local_5 == '\n') {
LAB_3b40e231:
                  _MaxCharCount = uVar7;
                  *(undefined *)psVar12 = 10;
                }
                else {
                  *(undefined *)psVar12 = 0xd;
                  *(char *)(iVar14 + 5 + *piVar6) = local_5;
                  _MaxCharCount = uVar7;
                }
              }
              psVar12 = (short *)((int)psVar12 + 1);
              uVar7 = _MaxCharCount;
            }
            else {
              *(char *)psVar12 = cVar4;
              psVar12 = (short *)((int)psVar12 + 1);
              uVar7 = _MaxCharCount + 1;
            }
LAB_3b40e2ac:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_10);
        }
        local_10 = (short *)((int)psVar12 - (int)local_14);
        if ((local_6 != '\x01') || (local_10 == (short *)0x0)) goto LAB_3b40e3b1;
        bVar3 = *(byte *)(short *)((int)psVar12 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar12 = (short *)((int)psVar12 + -1);
          while ((((&DAT_3b416ef0)[bVar3] == '\0' && (iVar13 < 5)) && (local_14 <= psVar12))) {
            psVar12 = (short *)((int)psVar12 + -1);
            bVar3 = *(byte *)psVar12;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_3b416ef0)[*(byte *)psVar12] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_3b40e3ad;
          }
          if ((char)(&DAT_3b416ef0)[*(byte *)psVar12] + 1 == iVar13) {
            psVar12 = (short *)((int)psVar12 + iVar13);
          }
          else if ((*(byte *)(*piVar6 + 4 + iVar14) & 0x48) == 0) {
            __lseeki64_nolock(_FileHandle,(longlong)-iVar13,1);
          }
          else {
            psVar8 = (short *)((int)psVar12 + 1);
            *(byte *)(*piVar6 + 5 + iVar14) = *(byte *)psVar12;
            if (1 < iVar13) {
              *(undefined *)(iVar14 + 0x25 + *piVar6) = *(undefined *)psVar8;
              psVar8 = psVar12 + 1;
            }
            if (iVar13 == 3) {
              *(undefined *)(iVar14 + 0x26 + *piVar6) = *(undefined *)psVar8;
              psVar8 = (short *)((int)psVar8 + 1);
            }
            psVar12 = (short *)((int)psVar8 - iVar13);
          }
        }
        iVar13 = (int)psVar12 - (int)local_14;
        local_10 = (short *)MultiByteToWideChar(0xfde9,0,(LPCSTR)local_14,iVar13,(LPWSTR)_DstBuf,
                                                uVar2 >> 1);
        if (local_10 != (short *)0x0) {
          bVar15 = local_10 != (short *)iVar13;
          local_10 = (short *)((int)local_10 * 2);
          *(uint *)(iVar14 + 0x30 + *piVar6) = (uint)bVar15;
          goto LAB_3b40e3b1;
        }
        uVar11 = GetLastError();
LAB_3b40e3a6:
        __dosmaperr(uVar11);
      }
LAB_3b40e3ad:
      local_18 = -1;
LAB_3b40e3b1:
      if (local_14 != (short *)_DstBuf) {
        _free(local_14);
      }
      if (local_18 == -2) {
        return (int)local_10;
      }
      return local_18;
    }
  }
LAB_3b40e092:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_3b40e0a4:
  FUN_3b408343();
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __read
// 
// Library: Visual Studio 2010 Release

int __cdecl __read(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    return -1;
  }
  if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_3b40e64a();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_3b40e5aa;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_3b40e5aa:
  FUN_3b408343();
  return -1;
}



void FUN_3b40e64a(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_3b417418 = _DAT_3b417418 + 1;
  pcVar1 = (char *)__malloc_crt(0x1000);
  _File->_base = pcVar1;
  if (pcVar1 == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_base = (char *)&_File->_charbuf;
    _File->_bufsiz = 2;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return;
}



int __cdecl FUN_3b40e69b(undefined4 *param_1,LPCSTR param_2,uint param_3,int param_4,byte param_5)

{
  byte *pbVar1;
  byte bVar2;
  uint *in_EAX;
  errno_t eVar3;
  uint uVar4;
  ulong *puVar5;
  int *piVar6;
  DWORD DVar7;
  long lVar8;
  int iVar9;
  HANDLE pvVar10;
  byte bVar11;
  int iVar12;
  bool bVar13;
  longlong lVar14;
  int iVar15;
  _SECURITY_ATTRIBUTES local_34;
  uint local_28;
  HANDLE local_24;
  uint local_20;
  DWORD local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  char local_8;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar13 = (param_3 & 0x80) == 0;
  local_28 = 0;
  local_6 = 0;
  local_c = 0;
  local_34.nLength = 0xc;
  local_34.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar13) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_34.bInheritHandle = (BOOL)bVar13;
  eVar3 = __get_fmode((int *)&local_28);
  if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_28 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar4 = param_3 & 3;
  if (uVar4 == 0) {
    local_10 = 0x80000000;
  }
  else {
    if (uVar4 == 1) {
      if (((param_3 & 8) == 0) || ((param_3 & 0x70000) == 0)) {
        local_10 = 0x40000000;
        goto LAB_3b40e75d;
      }
    }
    else if (uVar4 != 2) goto LAB_3b40e71d;
    local_10 = 0xc0000000;
  }
LAB_3b40e75d:
  if (param_4 == 0x10) {
    local_18 = 0;
  }
  else if (param_4 == 0x20) {
    local_18 = 1;
  }
  else if (param_4 == 0x30) {
    local_18 = 2;
  }
  else if (param_4 == 0x40) {
    local_18 = 3;
  }
  else {
    if (param_4 != 0x80) {
LAB_3b40e71d:
      puVar5 = ___doserrno();
      *puVar5 = 0;
      *in_EAX = 0xffffffff;
      piVar6 = __errno();
      *piVar6 = 0x16;
      FUN_3b408343();
      return 0x16;
    }
    local_18 = (uint)(local_10 == 0x80000000);
  }
  uVar4 = param_3 & 0x700;
  if (uVar4 < 0x401) {
    if ((uVar4 == 0x400) || (uVar4 == 0)) {
      local_1c = 3;
    }
    else if (uVar4 == 0x100) {
      local_1c = 4;
    }
    else {
      if (uVar4 == 0x200) goto LAB_3b40e81f;
      if (uVar4 != 0x300) goto LAB_3b40e7ff;
      local_1c = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_3b40e81f:
        local_1c = 5;
        goto LAB_3b40e82f;
      }
      if (uVar4 != 0x700) {
LAB_3b40e7ff:
        puVar5 = ___doserrno();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        piVar6 = __errno();
        *piVar6 = 0x16;
        FUN_3b408343();
        return 0x16;
      }
    }
    local_1c = 1;
  }
LAB_3b40e82f:
  local_14 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_3b417a80 & param_5))) {
    local_14 = 1;
  }
  if ((param_3 & 0x40) != 0) {
    local_14 = local_14 | 0x4000000;
    local_10 = local_10 | 0x10000;
    local_18 = local_18 | 4;
  }
  if ((param_3 & 0x1000) != 0) {
    local_14 = local_14 | 0x100;
  }
  if ((param_3 & 0x20) == 0) {
    if ((param_3 & 0x10) != 0) {
      local_14 = local_14 | 0x10000000;
    }
  }
  else {
    local_14 = local_14 | 0x8000000;
  }
  uVar4 = __alloc_osfhnd();
  *in_EAX = uVar4;
  if (uVar4 == 0xffffffff) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    piVar6 = __errno();
    *piVar6 = 0x18;
    piVar6 = __errno();
    return *piVar6;
  }
  *param_1 = 1;
  local_24 = CreateFileA(param_2,local_10,local_18,&local_34,local_1c,local_14,(HANDLE)0x0);
  if (local_24 == (HANDLE)0xffffffff) {
    if (((local_10 & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_10 = local_10 & 0x7fffffff;
      local_24 = CreateFileA(param_2,local_10,local_18,&local_34,local_1c,local_14,(HANDLE)0x0);
      if (local_24 != (HANDLE)0xffffffff) goto LAB_3b40e957;
    }
    pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_3b40e948;
  }
LAB_3b40e957:
  DVar7 = GetFileType(local_24);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_24);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_3b40e948;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_24);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_3b40ecbd;
    if ((param_3 & 2) == 0) goto LAB_3b40ea8b;
    lVar8 = __lseek_nolock(*in_EAX,-1,2);
    if (lVar8 == -1) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_3b40ea8b;
    }
    else {
      local_8 = '\0';
      iVar12 = __read_nolock(*in_EAX,&local_8,1);
      if ((((iVar12 != 0) || (local_8 != '\x1a')) ||
          (iVar12 = __chsize_nolock(*in_EAX,(longlong)lVar8), iVar12 != -1)) &&
         (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1)) goto LAB_3b40ea8b;
    }
LAB_3b40ea3c:
    __close_nolock(*in_EAX);
    goto LAB_3b40e948;
  }
LAB_3b40ea8b:
  local_5 = bVar11;
  if ((local_5 & 0x80) != 0) {
    if ((param_3 & 0x74000) == 0) {
      if ((local_28 & 0x74000) == 0) {
        param_3 = param_3 | 0x4000;
      }
      else {
        param_3 = param_3 | local_28 & 0x74000;
      }
    }
    uVar4 = param_3 & 0x74000;
    if (uVar4 == 0x4000) {
      local_6 = 0;
    }
    else if ((uVar4 == 0x10000) || (uVar4 == 0x14000)) {
      if ((param_3 & 0x301) == 0x301) goto LAB_3b40eafa;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_3b40eafa:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_20 = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_10 & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_1c == 0) goto LAB_3b40ecbd;
        if (2 < local_1c) {
          if (local_1c < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0,2);
            if (lVar14 == 0) goto LAB_3b40eb62;
            lVar14 = __lseeki64_nolock(*in_EAX,0,0);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_3b40ec27;
          }
LAB_3b40eb59:
          if (local_1c != 5) goto LAB_3b40ecbd;
        }
LAB_3b40eb62:
        iVar12 = 0;
        if (local_6 == 1) {
          local_20 = 0xbfbbef;
          iVar15 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_3b40ecbd;
          local_20 = 0xfeff;
          iVar15 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_20 + iVar12),iVar15 - iVar12);
          if (iVar9 == -1) goto LAB_3b40ea3c;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < iVar15);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_1c != 0)) {
            if (2 < local_1c) {
              if (4 < local_1c) goto LAB_3b40eb59;
              lVar14 = __lseeki64_nolock(*in_EAX,0,2);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,0);
                if (lVar14 == -1) goto LAB_3b40ea3c;
                goto LAB_3b40ebad;
              }
            }
            goto LAB_3b40eb62;
          }
          goto LAB_3b40ecbd;
        }
LAB_3b40ebad:
        iVar12 = __read_nolock(*in_EAX,&local_20,3);
        if (iVar12 == -1) goto LAB_3b40ea3c;
        if (iVar12 == 2) {
LAB_3b40ec34:
          if ((local_20 & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_20 & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_3b40ea3c;
            local_6 = 2;
            goto LAB_3b40ecbd;
          }
        }
        else if (iVar12 == 3) {
          if (local_20 == 0xbfbbef) {
            local_6 = 1;
            goto LAB_3b40ecbd;
          }
          goto LAB_3b40ec34;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_3b40ec27:
        if (uVar4 == 0xffffffff) goto LAB_3b40ea3c;
      }
    }
  }
LAB_3b40ecbd:
  pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if ((local_10 & 0xc0000000) != 0xc0000000) {
    return local_c;
  }
  if ((param_3 & 1) == 0) {
    return local_c;
  }
  CloseHandle(local_24);
  pvVar10 = CreateFileA(param_2,local_10 & 0x7fffffff,local_18,&local_34,3,local_14,(HANDLE)0x0);
  if (pvVar10 != (HANDLE)0xffffffff) {
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_3b418100)[(int)*in_EAX >> 5]) = pvVar10;
    return local_c;
  }
  DVar7 = GetLastError();
  __dosmaperr(DVar7);
  pbVar1 = (byte *)((&DAT_3b418100)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0xfe;
  __free_osfhnd(*in_EAX);
LAB_3b40e948:
  piVar6 = __errno();
  return *piVar6;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __sopen_helper
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__sopen_helper(char *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_3b4144c0;
  uStack_c = 0x3b40eddb;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (char *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_3b408343();
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = FUN_3b40e69b(local_20,_Filename,_OFlag,_ShFlag,(byte)_PMode);
    local_8 = (undefined *)0xfffffffe;
    FUN_3b40ee65();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_3b40ee65(void)

{
  byte *pbVar1;
  int unaff_EBP;
  uint *unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_EDI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_EDI) {
      pbVar1 = (byte *)((&DAT_3b418100)[(int)*unaff_ESI >> 5] + 4 + (*unaff_ESI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_ESI);
  }
  return;
}



// Library Function - Single Match
//  __sopen_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__sopen_s(int *_FileHandle,char *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionMode)

{
  errno_t eVar1;
  
  eVar1 = __sopen_helper(_Filename,_OpenFlag,_ShareFlag,_PermissionMode,_FileHandle,1);
  return eVar1;
}



// Library Function - Single Match
//  __mbsnbicmp_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbicmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  size_t sVar1;
  uchar *puVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  byte *pbVar6;
  _LocaleUpdate local_1c [4];
  int local_18;
  int local_14;
  char local_10;
  ushort local_c;
  ushort local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_1c,_Locale);
  if (_MaxCount == 0) {
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    iVar3 = 0;
  }
  else if (*(int *)(local_18 + 8) == 0) {
    iVar3 = __strnicmp((char *)_Str1,(char *)_Str2,_MaxCount);
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
  }
  else if (_Str1 == (uchar *)0x0) {
    piVar4 = __errno();
    *piVar4 = 0x16;
    FUN_3b408343();
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    iVar3 = 0x7fffffff;
  }
  else {
    if (_Str2 != (uchar *)0x0) {
      do {
        uVar5 = (uint)*_Str1;
        sVar1 = _MaxCount - 1;
        puVar2 = _Str1 + 1;
        if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) == 0) {
          if ((*(byte *)(uVar5 + local_18 + 0x1d) & 0x10) != 0) {
            uVar5 = (uint)*(byte *)(uVar5 + local_18 + 0x11d);
          }
          local_c = (ushort)uVar5;
          _Str1 = puVar2;
LAB_3b40f006:
          uVar5 = (uint)*_Str2;
          pbVar6 = _Str2 + 1;
          if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) == 0) {
            if ((*(byte *)(uVar5 + local_18 + 0x1d) & 0x10) != 0) {
              uVar5 = (uint)*(byte *)(uVar5 + local_18 + 0x11d);
            }
            goto LAB_3b40f076;
          }
          if (sVar1 == 0) {
LAB_3b40f01c:
            _MaxCount = sVar1;
            local_8 = 0;
          }
          else {
            sVar1 = _MaxCount - 2;
            if (*pbVar6 == 0) goto LAB_3b40f01c;
            local_8 = CONCAT11(*_Str2,*pbVar6);
            pbVar6 = _Str2 + 2;
            _MaxCount = sVar1;
            if ((local_8 < *(ushort *)(local_18 + 0x10)) || (*(ushort *)(local_18 + 0x12) < local_8)
               ) {
              if ((*(ushort *)(local_18 + 0x16) <= local_8) &&
                 (local_8 <= *(ushort *)(local_18 + 0x18))) {
                local_8 = local_8 + *(short *)(local_18 + 0x1a);
              }
            }
            else {
              local_8 = local_8 + *(short *)(local_18 + 0x14);
            }
          }
        }
        else {
          if (sVar1 != 0) {
            if (*puVar2 == '\0') {
              local_c = 0;
              _Str1 = puVar2;
            }
            else {
              local_c = CONCAT11(*_Str1,*puVar2);
              _Str1 = _Str1 + 2;
              if ((local_c < *(ushort *)(local_18 + 0x10)) ||
                 (*(ushort *)(local_18 + 0x12) < local_c)) {
                if ((*(ushort *)(local_18 + 0x16) <= local_c) &&
                   (local_c <= *(ushort *)(local_18 + 0x18))) {
                  local_c = local_c + *(short *)(local_18 + 0x1a);
                }
              }
              else {
                local_c = local_c + *(short *)(local_18 + 0x14);
              }
            }
            goto LAB_3b40f006;
          }
          uVar5 = (uint)*_Str2;
          if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) != 0) {
LAB_3b40f090:
            if (local_10 != '\0') {
              *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
            }
            return 0;
          }
          local_c = 0;
          pbVar6 = _Str2;
          _Str1 = puVar2;
LAB_3b40f076:
          local_8 = (ushort)uVar5;
          _MaxCount = sVar1;
        }
        if (local_8 != local_c) {
          iVar3 = (-(uint)(local_8 < local_c) & 2) - 1;
          if (local_10 == '\0') {
            return iVar3;
          }
          *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
          return iVar3;
        }
        if ((local_c == 0) || (_Str2 = pbVar6, _MaxCount == 0)) goto LAB_3b40f090;
      } while( true );
    }
    piVar4 = __errno();
    *piVar4 = 0x16;
    FUN_3b408343();
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    iVar3 = 0x7fffffff;
  }
  return iVar3;
}



// Library Function - Single Match
//  __mbsnbicmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbicmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __mbsnbcmp_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbcmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  size_t sVar1;
  int iVar2;
  int *piVar3;
  ushort uVar4;
  uint uVar5;
  byte *pbVar6;
  byte *pbVar7;
  _LocaleUpdate local_14 [4];
  int local_10;
  int local_c;
  char local_8;
  
  if (_MaxCount == 0) {
    return 0;
  }
  _LocaleUpdate::_LocaleUpdate(local_14,_Locale);
  if (*(int *)(local_10 + 8) == 0) {
    iVar2 = _strncmp((char *)_Str1,(char *)_Str2,_MaxCount);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  else if (_Str1 == (uchar *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_3b408343();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  else {
    if (_Str2 != (uchar *)0x0) {
      do {
        uVar5 = (uint)*_Str1;
        sVar1 = _MaxCount - 1;
        pbVar6 = _Str1 + 1;
        if ((*(byte *)(uVar5 + 0x1d + local_10) & 4) == 0) {
LAB_3b40f1c4:
          uVar4 = (ushort)uVar5;
          uVar5 = (uint)*_Str2;
          pbVar7 = _Str2 + 1;
          if ((*(byte *)(uVar5 + 0x1d + local_10) & 4) != 0) {
            if (sVar1 != 0) {
              sVar1 = _MaxCount - 2;
              if (*pbVar7 != 0) {
                uVar5 = (uint)CONCAT11(*_Str2,*pbVar7);
                pbVar7 = _Str2 + 2;
                goto LAB_3b40f1f2;
              }
            }
            _MaxCount = sVar1;
            uVar5 = 0;
            sVar1 = _MaxCount;
          }
        }
        else {
          if (sVar1 != 0) {
            if (*pbVar6 == 0) {
              uVar5 = 0;
            }
            else {
              uVar5 = (uint)CONCAT11(*_Str1,*pbVar6);
              pbVar6 = _Str1 + 2;
            }
            goto LAB_3b40f1c4;
          }
          uVar5 = (uint)*_Str2;
          uVar4 = 0;
          pbVar7 = _Str2;
          if ((*(byte *)(uVar5 + 0x1d + local_10) & 4) != 0) {
LAB_3b40f199:
            if (local_8 != '\0') {
              *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            }
            return 0;
          }
        }
LAB_3b40f1f2:
        _MaxCount = sVar1;
        if ((ushort)uVar5 != uVar4) {
          iVar2 = (-(uint)((ushort)uVar5 < uVar4) & 2) - 1;
          if (local_8 == '\0') {
            return iVar2;
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
          return iVar2;
        }
        if ((uVar4 == 0) || (_Str1 = pbVar6, _Str2 = pbVar7, _MaxCount == 0)) goto LAB_3b40f199;
      } while( true );
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_3b408343();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  return iVar2;
}



// Library Function - Single Match
//  __mbsnbcmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbcmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbcmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtLCMapStringA_stat(struct localeinfo_struct *,unsigned long,unsigned long,char
// const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2010 Release

int __cdecl
__crtLCMapStringA_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint _Size;
  bool bVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  uint cchWideChar;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *local_10;
  
  uVar2 = securityCookie ^ (uint)&stack0xfffffffc;
  pcVar3 = param_4;
  iVar7 = param_5;
  if (0 < param_5) {
    do {
      iVar7 = iVar7 + -1;
      if (*pcVar3 == '\0') goto LAB_3b40f267;
      pcVar3 = pcVar3 + 1;
    } while (iVar7 != 0);
    iVar7 = -1;
LAB_3b40f267:
    iVar7 = param_5 - iVar7;
    iVar4 = iVar7 + -1;
    bVar1 = iVar4 < param_5;
    param_5 = iVar4;
    if (bVar1) {
      param_5 = iVar7;
    }
  }
  if (param_8 == 0) {
    param_8 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_8,(uint)(param_9 != 0) * 8 + 1,param_4,param_5,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_3b40f40c;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar5 = cchWideChar * 2 + 8;
    if (uVar5 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffe0;
      local_10 = (undefined4 *)&stack0xffffffe0;
      if (&stack0x00000000 != (undefined *)0x20) {
LAB_3b40f2f7:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar5);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_3b40f2f7;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_3b40f40c;
  iVar7 = MultiByteToWideChar(param_8,1,param_4,param_5,(LPWSTR)local_10,cchWideChar);
  if ((iVar7 != 0) &&
     (uVar5 = LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)0x0,0), uVar5 != 0)
     ) {
    if ((param_3 & 0x400) == 0) {
      if (((int)uVar5 < 1) || (0xffffffe0 / uVar5 < 2)) {
        puVar6 = (undefined4 *)0x0;
      }
      else {
        _Size = uVar5 * 2 + 8;
        if (_Size < 0x401) {
          if (&stack0x00000000 == (undefined *)0x20) goto LAB_3b40f400;
          puVar6 = (undefined4 *)&stack0xffffffe8;
        }
        else {
          puVar6 = (undefined4 *)_malloc(_Size);
          if (puVar6 != (undefined4 *)0x0) {
            *puVar6 = 0xdddd;
            puVar6 = puVar6 + 2;
          }
        }
      }
      if (puVar6 != (undefined4 *)0x0) {
        iVar7 = LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)puVar6,uVar5);
        if (iVar7 != 0) {
          if (param_7 == 0) {
            param_7 = 0;
            param_6 = (LPSTR)0x0;
          }
          WideCharToMultiByte(param_8,0,(LPCWSTR)puVar6,uVar5,param_6,param_7,(LPCSTR)0x0,
                              (LPBOOL)0x0);
        }
        __freea(puVar6);
      }
    }
    else if ((param_7 != 0) && ((int)uVar5 <= param_7)) {
      LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)param_6,param_7);
    }
  }
LAB_3b40f400:
  __freea(local_10);
LAB_3b40f40c:
  iVar7 = ___security_check_cookie_4(uVar2 ^ (uint)&stack0xfffffffc);
  return iVar7;
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Library: Visual Studio 2010 Release

int __cdecl
___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,
                  int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError)

{
  int iVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Plocinfo);
  iVar1 = __crtLCMapStringA_stat
                    (&local_14,(ulong)_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,
                     _Code_page,_BError);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtGetStringTypeA_stat(struct localeinfo_struct *,unsigned long,char const
// *,int,unsigned short *,int,int,int)
// 
// Library: Visual Studio 2010 Release

int __cdecl
__crtGetStringTypeA_stat
          (localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,
          int param_6,int param_7,int param_8)

{
  uint _Size;
  uint uVar1;
  uint cchWideChar;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *lpWideCharStr;
  
  uVar1 = securityCookie ^ (uint)&stack0xfffffffc;
  if (param_6 == 0) {
    param_6 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_6,(uint)(param_7 != 0) * 8 + 1,param_3,param_4,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_3b40f539;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar2 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_3b40f4f3:
        lpWideCharStr = puVar2 + 2;
      }
    }
    else {
      puVar2 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar2;
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0xdddd;
        goto LAB_3b40f4f3;
      }
    }
  }
  if (lpWideCharStr != (undefined4 *)0x0) {
    _memset(lpWideCharStr,0,cchWideChar * 2);
    iVar3 = MultiByteToWideChar(param_6,1,param_3,param_4,(LPWSTR)lpWideCharStr,cchWideChar);
    if (iVar3 != 0) {
      GetStringTypeW(param_2,(LPCWSTR)lpWideCharStr,iVar3,param_5);
    }
    __freea(lpWideCharStr);
  }
LAB_3b40f539:
  iVar3 = ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 2010 Release

BOOL __cdecl
___crtGetStringTypeA
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  int iVar1;
  int in_stack_00000020;
  pthreadlocinfo in_stack_ffffffec;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,_Plocinfo);
  iVar1 = __crtGetStringTypeA_stat
                    ((localeinfo_struct *)&stack0xffffffec,_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType
                     ,_Code_page,in_stack_00000020,(int)in_stack_ffffffec);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lc_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    _free(param_1[1]);
    _free(param_1[2]);
    _free(param_1[3]);
    _free(param_1[4]);
    _free(param_1[5]);
    _free(param_1[6]);
    _free(*param_1);
    _free(param_1[8]);
    _free(param_1[9]);
    _free(param_1[10]);
    _free(param_1[0xb]);
    _free(param_1[0xc]);
    _free(param_1[0xd]);
    _free(param_1[7]);
    _free(param_1[0xe]);
    _free(param_1[0xf]);
    _free(param_1[0x10]);
    _free(param_1[0x11]);
    _free(param_1[0x12]);
    _free(param_1[0x13]);
    _free(param_1[0x14]);
    _free(param_1[0x15]);
    _free(param_1[0x16]);
    _free(param_1[0x17]);
    _free(param_1[0x18]);
    _free(param_1[0x19]);
    _free(param_1[0x1a]);
    _free(param_1[0x1b]);
    _free(param_1[0x1c]);
    _free(param_1[0x1d]);
    _free(param_1[0x1e]);
    _free(param_1[0x1f]);
    _free(param_1[0x20]);
    _free(param_1[0x21]);
    _free(param_1[0x22]);
    _free(param_1[0x23]);
    _free(param_1[0x24]);
    _free(param_1[0x25]);
    _free(param_1[0x26]);
    _free(param_1[0x27]);
    _free(param_1[0x28]);
    _free(param_1[0x29]);
    _free(param_1[0x2a]);
    _free(param_1[0x2f]);
    _free(param_1[0x30]);
    _free(param_1[0x31]);
    _free(param_1[0x32]);
    _free(param_1[0x33]);
    _free(param_1[0x34]);
    _free(param_1[0x2e]);
    _free(param_1[0x36]);
    _free(param_1[0x37]);
    _free(param_1[0x38]);
    _free(param_1[0x39]);
    _free(param_1[0x3a]);
    _free(param_1[0x3b]);
    _free(param_1[0x35]);
    _free(param_1[0x3c]);
    _free(param_1[0x3d]);
    _free(param_1[0x3e]);
    _free(param_1[0x3f]);
    _free(param_1[0x40]);
    _free(param_1[0x41]);
    _free(param_1[0x42]);
    _free(param_1[0x43]);
    _free(param_1[0x44]);
    _free(param_1[0x45]);
    _free(param_1[0x46]);
    _free(param_1[0x47]);
    _free(param_1[0x48]);
    _free(param_1[0x49]);
    _free(param_1[0x4a]);
    _free(param_1[0x4b]);
    _free(param_1[0x4c]);
    _free(param_1[0x4d]);
    _free(param_1[0x4e]);
    _free(param_1[0x4f]);
    _free(param_1[0x50]);
    _free(param_1[0x51]);
    _free(param_1[0x52]);
    _free(param_1[0x53]);
    _free(param_1[0x54]);
    _free(param_1[0x55]);
    _free(param_1[0x56]);
    _free(param_1[0x57]);
    _free(param_1[0x58]);
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_num
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_3b416ff8) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_3b416ffc) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_3b417000) {
      _free(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_3b417028) {
      _free(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_3b41702c) {
      _free(param_1[0xd]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_3b417004) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_3b417008) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_3b41700c) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_3b417010) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_3b417014) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_3b417018) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_3b41701c) {
      _free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_3b417030) {
      _free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_3b417034) {
      _free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_3b417038) {
      _free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_3b41703c) {
      _free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_3b417040) {
      _free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_3b417044) {
      _free(*(undefined **)(param_1 + 0x4c));
    }
  }
  return;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  uVar1 = *(ushort *)(*(int *)(local_14[0] + 200) + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



// Library Function - Single Match
//  _isleadbyte
// 
// Library: Visual Studio 2010 Release

int __cdecl _isleadbyte(int _C)

{
  int iVar1;
  
  iVar1 = __isleadbyte_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  _strcspn
// 
// Library: Visual Studio

size_t __cdecl _strcspn(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  size_t sVar3;
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
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  sVar3 = 0xffffffff;
  do {
    sVar3 = sVar3 + 1;
    bVar1 = *_Str;
    if (bVar1 == 0) {
      return sVar3;
    }
    _Str = (char *)((byte *)_Str + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return sVar3;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar1 = (undefined4 *)((_Size - 4) + (int)_Src);
    puVar4 = (undefined4 *)((_Size - 4) + (int)_Dst);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = _Size >> 2;
      uVar3 = _Size & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return _Dst;
        case 2:
          goto switchD_3b40fcef_caseD_2;
        case 3:
          goto switchD_3b40fcef_caseD_3;
        }
        goto switchD_3b40fcef_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_3b40fcef_caseD_0;
      case 1:
        goto switchD_3b40fcef_caseD_1;
      case 2:
        goto switchD_3b40fcef_caseD_2;
      case 3:
        goto switchD_3b40fcef_caseD_3;
      default:
        uVar2 = _Size - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          puVar1 = (undefined4 *)((int)puVar1 + -1);
          uVar2 = uVar2 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_3b40fcef_caseD_2;
            case 3:
              goto switchD_3b40fcef_caseD_3;
            }
            goto switchD_3b40fcef_caseD_1;
          }
          break;
        case 2:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          puVar1 = (undefined4 *)((int)puVar1 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_3b40fcef_caseD_2;
            case 3:
              goto switchD_3b40fcef_caseD_3;
            }
            goto switchD_3b40fcef_caseD_1;
          }
          break;
        case 3:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
          puVar1 = (undefined4 *)((int)puVar1 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_3b40fcef_caseD_2;
            case 3:
              goto switchD_3b40fcef_caseD_3;
            }
            goto switchD_3b40fcef_caseD_1;
          }
        }
      }
    }
    switch(uVar2) {
    case 7:
      puVar4[7 - uVar2] = puVar1[7 - uVar2];
    case 6:
      puVar4[6 - uVar2] = puVar1[6 - uVar2];
    case 5:
      puVar4[5 - uVar2] = puVar1[5 - uVar2];
    case 4:
      puVar4[4 - uVar2] = puVar1[4 - uVar2];
    case 3:
      puVar4[3 - uVar2] = puVar1[3 - uVar2];
    case 2:
      puVar4[2 - uVar2] = puVar1[2 - uVar2];
    case 1:
      puVar4[1 - uVar2] = puVar1[1 - uVar2];
      puVar1 = puVar1 + -uVar2;
      puVar4 = puVar4 + -uVar2;
    }
    switch(uVar3) {
    case 1:
switchD_3b40fcef_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_3b40fcef_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_3b40fcef_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_3b40fcef_caseD_0:
    return _Dst;
  }
  if (((0x7f < _Size) && (DAT_3b4180e8 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
    puVar1 = __VEC_memcpy(_Size);
    return puVar1;
  }
  puVar1 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
    uVar2 = _Size >> 2;
    uVar3 = _Size & 3;
    if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *_Src;
        _Src = (undefined4 *)((int)_Src + 4);
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return _Dst;
      case 2:
        goto switchD_3b40fb69_caseD_2;
      case 3:
        goto switchD_3b40fb69_caseD_3;
      }
      goto switchD_3b40fb69_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_3b40fb69_caseD_0;
    case 1:
      goto switchD_3b40fb69_caseD_1;
    case 2:
      goto switchD_3b40fb69_caseD_2;
    case 3:
      goto switchD_3b40fb69_caseD_3;
    default:
      uVar2 = (_Size - 4) + ((uint)_Dst & 3);
      switch((uint)_Dst & 3) {
      case 1:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 2) = *(undefined *)((int)_Src + 2);
        _Src = (void *)((int)_Src + 3);
        puVar1 = (undefined4 *)((int)_Dst + 3);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_3b40fb69_caseD_2;
          case 3:
            goto switchD_3b40fb69_caseD_3;
          }
          goto switchD_3b40fb69_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        _Src = (void *)((int)_Src + 2);
        puVar1 = (undefined4 *)((int)_Dst + 2);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_3b40fb69_caseD_2;
          case 3:
            goto switchD_3b40fb69_caseD_3;
          }
          goto switchD_3b40fb69_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        _Src = (void *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)_Dst + 1);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_3b40fb69_caseD_2;
          case 3:
            goto switchD_3b40fb69_caseD_3;
          }
          goto switchD_3b40fb69_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar2) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 7] = *(undefined4 *)((int)_Src + (uVar2 - 7) * 4);
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = *(undefined4 *)((int)_Src + (uVar2 - 6) * 4);
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = *(undefined4 *)((int)_Src + (uVar2 - 5) * 4);
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = *(undefined4 *)((int)_Src + (uVar2 - 4) * 4);
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = *(undefined4 *)((int)_Src + (uVar2 - 3) * 4);
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = *(undefined4 *)((int)_Src + (uVar2 - 2) * 4);
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = *(undefined4 *)((int)_Src + (uVar2 - 1) * 4);
    _Src = (void *)((int)_Src + uVar2 * 4);
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_3b40fb69_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_3b40fb69_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_3b40fb69_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_3b40fb69_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _strncmp
// 
// Library: Visual Studio 2010 Release

int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  byte *pbVar1;
  uint uVar2;
  byte *pbVar3;
  uint uVar4;
  uint local_8;
  
  local_8 = 0;
  if (_MaxCount != 0) {
    if ((3 < _MaxCount) && (pbVar1 = (byte *)_Str1, pbVar3 = (byte *)_Str2, _MaxCount != 4)) {
      do {
        _Str1 = (char *)(pbVar1 + 4);
        _Str2 = (char *)(pbVar3 + 4);
        if ((*pbVar1 == 0) || (*pbVar1 != *pbVar3)) {
          uVar2 = (uint)*pbVar1;
          uVar4 = (uint)*pbVar3;
          goto LAB_3b40ff2d;
        }
        if ((pbVar1[1] == 0) || (pbVar1[1] != pbVar3[1])) {
          uVar2 = (uint)pbVar1[1];
          uVar4 = (uint)pbVar3[1];
          goto LAB_3b40ff2d;
        }
        if ((pbVar1[2] == 0) || (pbVar1[2] != pbVar3[2])) {
          uVar2 = (uint)pbVar1[2];
          uVar4 = (uint)pbVar3[2];
          goto LAB_3b40ff2d;
        }
        if ((pbVar1[3] == 0) || (pbVar1[3] != pbVar3[3])) {
          uVar2 = (uint)pbVar1[3];
          uVar4 = (uint)pbVar3[3];
          goto LAB_3b40ff2d;
        }
        local_8 = local_8 + 4;
        pbVar1 = (byte *)_Str1;
        pbVar3 = (byte *)_Str2;
      } while (local_8 < _MaxCount - 4);
    }
    for (; local_8 < _MaxCount; local_8 = local_8 + 1) {
      if ((*_Str1 == 0) || (*_Str1 != *_Str2)) {
        uVar2 = (uint)(byte)*_Str1;
        uVar4 = (uint)(byte)*_Str2;
LAB_3b40ff2d:
        return uVar2 - uVar4;
      }
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = (char *)((byte *)_Str2 + 1);
    }
  }
  return 0;
}



// Library Function - Single Match
//  _strpbrk
// 
// Library: Visual Studio

char * __cdecl _strpbrk(char *_Str,char *_Control)

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
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(char *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2010 Release

longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  byte *pbVar1;
  HANDLE hFile;
  int *piVar2;
  DWORD DVar3;
  DWORD DVar4;
  LONG local_8;
  
  local_8 = _Offset._4_4_;
  hFile = (HANDLE)__get_osfhandle(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_3b40ffb1:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,(LONG)_Offset,&local_8,_Origin);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_3b40ffb1;
      }
    }
    pbVar1 = (byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,DVar3);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseeki64
// 
// Library: Visual Studio 2010 Release

longlong __cdecl __lseeki64(int _FileHandle,longlong _Offset,int _Origin)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  undefined8 local_28;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_3b4100e5();
        goto LAB_3b4100df;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_3b408343();
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_3b4100df:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_3b4100e5(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 2010 Release

int __cdecl __isatty(int _FileHandle)

{
  int *piVar1;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_3b4180ec)) {
      return (int)*(char *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
             0x40;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_3b408343();
  }
  return 0;
}



bool FUN_3b410145(void)

{
  return DAT_3b4180dc == (securityCookie | 1);
}



// Library Function - Single Match
//  __wctomb_s_l
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,_locale_t _Locale)

{
  char *lpMultiByteStr;
  size_t _Size;
  int iVar1;
  int *piVar2;
  DWORD DVar3;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _Size = _SizeInBytes;
  lpMultiByteStr = _MbCh;
  if ((_MbCh == (char *)0x0) && (_SizeInBytes != 0)) {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = 0;
    }
LAB_3b41017f:
    iVar1 = 0;
  }
  else {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = -1;
    }
    if (0x7fffffff < _SizeInBytes) {
      piVar2 = __errno();
      *piVar2 = 0x16;
      FUN_3b408343();
      return 0x16;
    }
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      if ((ushort)_WCh < 0x100) {
        if (lpMultiByteStr != (char *)0x0) {
          if (_Size == 0) goto LAB_3b41020b;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_3b41023a:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_3b41017f;
      }
      if ((lpMultiByteStr != (char *)0x0) && (_Size != 0)) {
        _memset(lpMultiByteStr,0,_Size);
      }
    }
    else {
      _MbCh = (char *)0x0;
      iVar1 = WideCharToMultiByte(*(UINT *)(local_14[0] + 4),0,&_WCh,1,lpMultiByteStr,_Size,
                                  (LPCSTR)0x0,(LPBOOL)&_MbCh);
      if (iVar1 == 0) {
        DVar3 = GetLastError();
        if (DVar3 == 0x7a) {
          if ((lpMultiByteStr != (char *)0x0) && (_Size != 0)) {
            _memset(lpMultiByteStr,0,_Size);
          }
LAB_3b41020b:
          piVar2 = __errno();
          *piVar2 = 0x22;
          FUN_3b408343();
          if (local_8 == '\0') {
            return 0x22;
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
          return 0x22;
        }
      }
      else if (_MbCh == (char *)0x0) {
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = iVar1;
        }
        goto LAB_3b41023a;
      }
    }
    piVar2 = __errno();
    *piVar2 = 0x2a;
    piVar2 = __errno();
    iVar1 = *piVar2;
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  _wctomb_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = __wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __isdigit_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isdigit_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = *(ushort *)(local_14.locinfo[1].lc_category[0].locale + _C * 2) & 4;
  }
  else {
    uVar1 = __isctype_l(_C,4,&local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isdigit
// 
// Library: Visual Studio 2010 Release

int __cdecl _isdigit(int _C)

{
  int iVar1;
  
  if (DAT_3b417adc == 0) {
    return *(ushort *)(PTR_DAT_3b416d68 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isxdigit_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isxdigit_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = *(ushort *)(local_14.locinfo[1].lc_category[0].locale + _C * 2) & 0x80;
  }
  else {
    uVar1 = __isctype_l(_C,0x80,&local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isxdigit
// 
// Library: Visual Studio 2010 Release

int __cdecl _isxdigit(int _C)

{
  int iVar1;
  
  if (DAT_3b417adc == 0) {
    return *(ushort *)(PTR_DAT_3b416d68 + _C * 2) & 0x80;
  }
  iVar1 = __isxdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isspace_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isspace_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = *(ushort *)(local_14.locinfo[1].lc_category[0].locale + _C * 2) & 8;
  }
  else {
    uVar1 = __isctype_l(_C,8,&local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isspace
// 
// Library: Visual Studio 2010 Release

int __cdecl _isspace(int _C)

{
  int iVar1;
  
  if (DAT_3b417adc == 0) {
    return *(ushort *)(PTR_DAT_3b416d68 + _C * 2) & 8;
  }
  iVar1 = __isspace_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __ungetc_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __ungetc_nolock(int _Ch,FILE *_File)

{
  char *pcVar1;
  uint uVar2;
  int *piVar3;
  undefined *puVar4;
  
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    uVar2 = __fileno(_File);
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar4 = &DAT_3b4165d0;
    }
    else {
      puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar2 >> 5]);
    }
    if ((puVar4[0x24] & 0x7f) == 0) {
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar4 = &DAT_3b4165d0;
      }
      else {
        puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_3b418100)[(int)uVar2 >> 5]);
      }
      if ((puVar4[0x24] & 0x80) == 0) goto LAB_3b4104d4;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_3b408343();
  }
  else {
LAB_3b4104d4:
    if (_Ch != -1) {
      uVar2 = _File->_flag;
      if (((uVar2 & 1) != 0) || (((char)uVar2 < '\0' && ((uVar2 & 2) == 0)))) {
        if (_File->_base == (char *)0x0) {
          __getbuf(_File);
        }
        if (_File->_ptr == _File->_base) {
          if (_File->_cnt != 0) {
            return -1;
          }
          _File->_ptr = _File->_ptr + 1;
        }
        _File->_ptr = _File->_ptr + -1;
        pcVar1 = _File->_ptr;
        if ((*(byte *)&_File->_flag & 0x40) == 0) {
          *pcVar1 = (char)_Ch;
        }
        else if (*pcVar1 != (char)_Ch) {
          _File->_ptr = pcVar1 + 1;
          return -1;
        }
        _File->_cnt = _File->_cnt + 1;
        _File->_flag = _File->_flag & 0xffffffefU | 1;
        return _Ch & 0xff;
      }
    }
  }
  return -1;
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  wchar_t *pwVar1;
  int iVar2;
  int *piVar3;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if ((_SrcCh != (char *)0x0) && (_SrcSizeInBytes != 0)) {
    if (*_SrcCh != '\0') {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
      if ((local_14.locinfo)->lc_category[0].wlocale != (wchar_t *)0x0) {
        iVar2 = __isleadbyte_l((uint)(byte)*_SrcCh,&local_14);
        if (iVar2 == 0) {
          iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,1,_DstCh,
                                      (uint)(_DstCh != (wchar_t *)0x0));
          if (iVar2 != 0) goto LAB_3b410582;
        }
        else {
          pwVar1 = (local_14.locinfo)->locale_name[3];
          if ((((1 < (int)pwVar1) && ((int)pwVar1 <= (int)_SrcSizeInBytes)) &&
              (iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,(int)pwVar1,
                                           _DstCh,(uint)(_DstCh != (wchar_t *)0x0)), iVar2 != 0)) ||
             (((local_14.locinfo)->locale_name[3] <= _SrcSizeInBytes && (_SrcCh[1] != '\0')))) {
            pwVar1 = (local_14.locinfo)->locale_name[3];
            if (local_8 == '\0') {
              return (int)pwVar1;
            }
            *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            return (int)pwVar1;
          }
        }
        piVar3 = __errno();
        *piVar3 = 0x2a;
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return -1;
      }
      if (_DstCh != (wchar_t *)0x0) {
        *_DstCh = (ushort)(byte)*_SrcCh;
      }
LAB_3b410582:
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 1;
    }
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = L'\0';
    }
  }
  return 0;
}



// Library Function - Single Match
//  _mbtowc
// 
// Library: Visual Studio 2010 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  int __cdecl x_ismbbtype_l(struct localeinfo_struct *,unsigned int,int,int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl x_ismbbtype_l(localeinfo_struct *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  int local_14;
  int local_10;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,param_1);
  if ((*(byte *)(local_10 + 0x1d + (param_2 & 0xff)) & (byte)param_4) == 0) {
    if (param_3 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = (uint)*(ushort *)(*(int *)(local_14 + 200) + (param_2 & 0xff) * 2) & param_3;
    }
    if (uVar1 == 0) goto LAB_3b4106a8;
  }
  uVar1 = 1;
LAB_3b4106a8:
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  __ismbblead
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __ismbblead(uint _C)

{
  int iVar1;
  
  iVar1 = x_ismbbtype_l((localeinfo_struct *)0x0,_C,0,4);
  return iVar1;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio 2010 Release

uint __alloca_probe_16(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 0xf;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_8
// 
// Library: Visual Studio

uint __alloca_probe_8(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 7;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// Library Function - Single Match
//  __VEC_memcpy
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

undefined4 * __fastcall __VEC_memcpy(uint param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  uint uVar16;
  uint uVar17;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 *puVar18;
  
  puVar18 = unaff_EDI;
  if (((uint)unaff_ESI & 0xf) != 0) {
    uVar17 = 0x10 - ((uint)unaff_ESI & 0xf);
    param_1 = param_1 - uVar17;
    for (uVar16 = uVar17 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
      *(undefined *)puVar18 = *(undefined *)unaff_ESI;
      unaff_ESI = (undefined4 *)((int)unaff_ESI + 1);
      puVar18 = (undefined4 *)((int)puVar18 + 1);
    }
    for (uVar17 = uVar17 >> 2; uVar17 != 0; uVar17 = uVar17 - 1) {
      *puVar18 = *unaff_ESI;
      unaff_ESI = unaff_ESI + 1;
      puVar18 = puVar18 + 1;
    }
  }
  for (uVar16 = param_1 >> 7; uVar16 != 0; uVar16 = uVar16 - 1) {
    uVar1 = unaff_ESI[1];
    uVar2 = unaff_ESI[2];
    uVar3 = unaff_ESI[3];
    uVar4 = unaff_ESI[4];
    uVar5 = unaff_ESI[5];
    uVar6 = unaff_ESI[6];
    uVar7 = unaff_ESI[7];
    uVar8 = unaff_ESI[8];
    uVar9 = unaff_ESI[9];
    uVar10 = unaff_ESI[10];
    uVar11 = unaff_ESI[0xb];
    uVar12 = unaff_ESI[0xc];
    uVar13 = unaff_ESI[0xd];
    uVar14 = unaff_ESI[0xe];
    uVar15 = unaff_ESI[0xf];
    *puVar18 = *unaff_ESI;
    puVar18[1] = uVar1;
    puVar18[2] = uVar2;
    puVar18[3] = uVar3;
    puVar18[4] = uVar4;
    puVar18[5] = uVar5;
    puVar18[6] = uVar6;
    puVar18[7] = uVar7;
    puVar18[8] = uVar8;
    puVar18[9] = uVar9;
    puVar18[10] = uVar10;
    puVar18[0xb] = uVar11;
    puVar18[0xc] = uVar12;
    puVar18[0xd] = uVar13;
    puVar18[0xe] = uVar14;
    puVar18[0xf] = uVar15;
    uVar1 = unaff_ESI[0x11];
    uVar2 = unaff_ESI[0x12];
    uVar3 = unaff_ESI[0x13];
    uVar4 = unaff_ESI[0x14];
    uVar5 = unaff_ESI[0x15];
    uVar6 = unaff_ESI[0x16];
    uVar7 = unaff_ESI[0x17];
    uVar8 = unaff_ESI[0x18];
    uVar9 = unaff_ESI[0x19];
    uVar10 = unaff_ESI[0x1a];
    uVar11 = unaff_ESI[0x1b];
    uVar12 = unaff_ESI[0x1c];
    uVar13 = unaff_ESI[0x1d];
    uVar14 = unaff_ESI[0x1e];
    uVar15 = unaff_ESI[0x1f];
    puVar18[0x10] = unaff_ESI[0x10];
    puVar18[0x11] = uVar1;
    puVar18[0x12] = uVar2;
    puVar18[0x13] = uVar3;
    puVar18[0x14] = uVar4;
    puVar18[0x15] = uVar5;
    puVar18[0x16] = uVar6;
    puVar18[0x17] = uVar7;
    puVar18[0x18] = uVar8;
    puVar18[0x19] = uVar9;
    puVar18[0x1a] = uVar10;
    puVar18[0x1b] = uVar11;
    puVar18[0x1c] = uVar12;
    puVar18[0x1d] = uVar13;
    puVar18[0x1e] = uVar14;
    puVar18[0x1f] = uVar15;
    unaff_ESI = unaff_ESI + 0x20;
    puVar18 = puVar18 + 0x20;
  }
  if ((param_1 & 0x7f) != 0) {
    for (uVar16 = (param_1 & 0x7f) >> 4; uVar16 != 0; uVar16 = uVar16 - 1) {
      uVar1 = unaff_ESI[1];
      uVar2 = unaff_ESI[2];
      uVar3 = unaff_ESI[3];
      *puVar18 = *unaff_ESI;
      puVar18[1] = uVar1;
      puVar18[2] = uVar2;
      puVar18[3] = uVar3;
      unaff_ESI = unaff_ESI + 4;
      puVar18 = puVar18 + 4;
    }
    if ((param_1 & 0xf) != 0) {
      for (uVar16 = (param_1 & 0xf) >> 2; uVar16 != 0; uVar16 = uVar16 - 1) {
        *puVar18 = *unaff_ESI;
        unaff_ESI = unaff_ESI + 1;
        puVar18 = puVar18 + 1;
      }
      for (uVar16 = param_1 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
        *(undefined *)puVar18 = *(undefined *)unaff_ESI;
        unaff_ESI = (undefined4 *)((int)unaff_ESI + 1);
        puVar18 = (undefined4 *)((int)puVar18 + 1);
      }
    }
  }
  return unaff_EDI;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2010 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  DWORD local_8;
  
  if (DAT_3b417060 == (HANDLE)0xfffffffe) {
    ___initconout();
  }
  if (DAT_3b417060 != (HANDLE)0xffffffff) {
    BVar1 = WriteConsoleW(DAT_3b417060,&_WCh,1,&local_8,(LPVOID)0x0);
    if (BVar1 != 0) {
      return _WCh;
    }
  }
  return 0xffff;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio 2010 Release

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __chsize_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __chsize_nolock(int _FileHandle,longlong _Size)

{
  int iVar1;
  HANDLE pvVar2;
  LPVOID _Buf;
  int *piVar3;
  int iVar4;
  uint uVar5;
  ulong *puVar6;
  BOOL BVar7;
  uint uVar8;
  int iVar9;
  bool bVar10;
  bool bVar11;
  longlong lVar12;
  longlong lVar13;
  DWORD DVar14;
  SIZE_T dwBytes;
  uint local_14;
  uint local_10;
  
  local_14 = 0;
  local_10 = 0;
  lVar12 = __lseeki64_nolock(_FileHandle,0,1);
  if (lVar12 == -1) goto LAB_3b410903;
  lVar13 = __lseeki64_nolock(_FileHandle,0,2);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_3b410903;
  uVar8 = (uint)_Size - (uint)lVar13;
  uVar5 = (uint)((uint)_Size < (uint)lVar13);
  iVar1 = _Size._4_4_ - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4(_Size._4_4_,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size,0);
      if (lVar13 == -1) goto LAB_3b410903;
      pvVar2 = (HANDLE)__get_osfhandle(_FileHandle);
      BVar7 = SetEndOfFile(pvVar2);
      local_14 = (BVar7 != 0) - 1;
      local_10 = (int)local_14 >> 0x1f;
      if ((local_14 & local_10) == 0xffffffff) {
        piVar3 = __errno();
        *piVar3 = 0xd;
        puVar6 = ___doserrno();
        DVar14 = GetLastError();
        *puVar6 = DVar14;
        goto LAB_3b410a01;
      }
    }
  }
  else {
    dwBytes = 0x1000;
    DVar14 = 8;
    pvVar2 = GetProcessHeap();
    _Buf = HeapAlloc(pvVar2,DVar14,dwBytes);
    if (_Buf == (LPVOID)0x0) {
      piVar3 = __errno();
      *piVar3 = 0xc;
      goto LAB_3b410903;
    }
    iVar4 = __setmode_nolock(_FileHandle,0x8000);
    while( true ) {
      uVar5 = uVar8;
      if ((-1 < iVar9) && ((0 < iVar9 || (0xfff < uVar8)))) {
        uVar5 = 0x1000;
      }
      uVar5 = __write_nolock(_FileHandle,_Buf,uVar5);
      if (uVar5 == 0xffffffff) break;
      bVar10 = uVar8 < uVar5;
      uVar8 = uVar8 - uVar5;
      bVar11 = SBORROW4(iVar9,(int)uVar5 >> 0x1f);
      iVar1 = iVar9 - ((int)uVar5 >> 0x1f);
      iVar9 = iVar1 - (uint)bVar10;
      if ((iVar9 < 0) ||
         ((iVar9 == 0 || (bVar11 != SBORROW4(iVar1,(uint)bVar10)) != iVar9 < 0 && (uVar8 == 0))))
      goto LAB_3b410955;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_3b410955:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_3b410a01:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_3b410903;
  }
  lVar12 = __lseeki64_nolock(_FileHandle,lVar12,0);
  if (lVar12 != -1) {
    return 0;
  }
LAB_3b410903:
  piVar3 = __errno();
  return *piVar3;
}



// Library Function - Single Match
//  __lseek_nolock
// 
// Library: Visual Studio 2010 Release

long __cdecl __lseek_nolock(int _FileHandle,long _Offset,int _Origin)

{
  byte *pbVar1;
  HANDLE hFile;
  int *piVar2;
  DWORD DVar3;
  ulong uVar4;
  
  hFile = (HANDLE)__get_osfhandle(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
    DVar3 = 0xffffffff;
  }
  else {
    DVar3 = SetFilePointer(hFile,_Offset,(PLONG)0x0,_Origin);
    if (DVar3 == 0xffffffff) {
      uVar4 = GetLastError();
    }
    else {
      uVar4 = 0;
    }
    if (uVar4 == 0) {
      pbVar1 = (byte *)((&DAT_3b418100)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      __dosmaperr(uVar4);
      DVar3 = 0xffffffff;
    }
  }
  return DVar3;
}



// Library Function - Single Match
//  __setmode_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __setmode_nolock(int _FileHandle,int _Mode)

{
  int *piVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  byte *pbVar5;
  byte bVar6;
  int iVar7;
  
  piVar1 = &DAT_3b418100 + (_FileHandle >> 5);
  iVar7 = (_FileHandle & 0x1fU) * 0x40;
  iVar4 = *piVar1 + iVar7;
  cVar2 = *(char *)(iVar4 + 0x24);
  bVar3 = *(byte *)(iVar4 + 4);
  if (_Mode == 0x4000) {
    *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
    pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
    *pbVar5 = *pbVar5 & 0x80;
  }
  else if (_Mode == 0x8000) {
    *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) & 0x7f;
  }
  else {
    if ((_Mode == 0x10000) || (_Mode == 0x20000)) {
      *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x82 | 2;
    }
    else {
      if (_Mode != 0x40000) goto LAB_3b410b43;
      *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_3b410b43:
  if ((bVar3 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar2 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



// Library Function - Single Match
//  __get_fmode
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl __get_fmode(int *_PMode)

{
  int *piVar1;
  
  if (_PMode == (int *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_3b408343();
    return 0x16;
  }
  *_PMode = DAT_3b4180e0;
  return 0;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2010 Release

void __cdecl ___initconout(void)

{
  DAT_3b417060 = CreateFileW(L"CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x3b410bc4. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


