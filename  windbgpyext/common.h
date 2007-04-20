#pragma once
// Python.h crap
#ifdef _DEBUG
  #undef _DEBUG
  #include <Python.h>
  #define _DEBUG
#else
  #include <Python.h>
#endif

// windbg crap
#include <Windows.h>
#define KDEXT_64BIT
#include <wdbgexts.h>

#define BUFSIZE (1024)
