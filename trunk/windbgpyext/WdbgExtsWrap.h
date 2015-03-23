#pragma once

#define WIPE_MODULE_NAME "wipe"

PyObject * wipe_dprintf(PyObject *self, PyObject *args);
PyObject * wipe_CheckControlC(PyObject *self, PyObject *args);
PyObject * wipe_Disasm(PyObject *self, PyObject *args);
PyObject * wipe_GetExpression(PyObject * self, PyObject * args);
PyObject * wipe_GetKdContext(PyObject * self, PyObject * args);
PyObject * wipe_ReadMemory(PyObject * self, PyObject * args);
PyObject * wipe_WriteMemory(PyObject * self, PyObject * args);
PyObject * wipe_ReadMsr(PyObject * self, PyObject * args);
PyObject * wipe_WriteMsr(PyObject * self, PyObject * args);
PyObject * wipe_ReadPhysical(PyObject * self, PyObject * args);
PyObject * wipe_WritePhysical(PyObject * self, PyObject * args);
PyObject * wipe_GetSymbol(PyObject * self, PyObject * args);
PyObject * wipe_GetContext(PyObject * self, PyObject * args);
PyObject * wipe_SetContext(PyObject * self, PyObject * args);
PyObject * wipe_StackTrace(PyObject * self, PyObject * args);