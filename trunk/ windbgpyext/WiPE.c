/*** Includes ****************************************************/

#include "common.h"
#include "WdbgExtsWrap.h"

/*** definitions *************************************************/

#define WIPE_VERSION_MAJOR (5)
#define WIPE_VERSION_MINOR (5)

/*** Globals *****************************************************/

static PyMethodDef WipeMethods[] = {
    {"dprintf", wipe_dprintf, METH_VARARGS, "writes a string to the console"},
	{"CheckControlC", wipe_CheckControlC, METH_VARARGS, "checks if user pressed ctrl+c"},
	{"Disasm", wipe_Disasm, METH_VARARGS, "Disassembles an instruction"},
	{"GetExpression", wipe_GetExpression, METH_VARARGS, "Evaluate an expression"},
	{"GetKdContext", wipe_GetKdContext, METH_VARARGS, "Processor Context"},
	{"ReadMemory", wipe_ReadMemory, METH_VARARGS, "Read process memory"},
	{"WriteMemory", wipe_WriteMemory, METH_VARARGS, "Write process memory"},
	{"ReadMsr", wipe_ReadMsr, METH_VARARGS, "Reads the value of a MSR"},
	{"WriteMsr", wipe_WriteMsr, METH_VARARGS, "Writes the value of a MSR"},
	{"ReadPhysical", wipe_ReadPhysical, METH_VARARGS, "Read physical memory"},
	{"WritePhysical", wipe_WritePhysical, METH_VARARGS, "Write physical memory"},
	{"GetSymbol", wipe_GetSymbol, METH_VARARGS, "Gets a symbol"},
	{"GetContext", wipe_GetContext, METH_VARARGS, "Gets a context for a thread"},
	{"SetContext", wipe_SetContext, METH_VARARGS, "Sets a context for a thread"},
    {NULL, NULL, 0, NULL}
};

WINDBG_EXTENSION_APIS64 ExtensionApis = {0,};

/*** Implementation **********************************************/

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  dwReason, 
                       LPVOID lpReserved
					 )
{
	UNREFERENCED_PARAMETER(lpReserved);
	
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			// We've just arrived...
			(VOID)DisableThreadLibraryCalls(hModule);
		}		
		case DLL_PROCESS_DETACH:
		default:
			break;
	}

    return TRUE;
}

LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(VOID)
{
	static EXT_API_VERSION tVersion= {WIPE_VERSION_MAJOR, WIPE_VERSION_MINOR, EXT_API_VERSION_NUMBER64, 0};
	return &tVersion;
}

VOID WDBGAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS64 lpExtensionApis,
								    USHORT MajorVersion,
								    USHORT MinorVersion)
{
	// Keep api given to us
	ExtensionApis = *lpExtensionApis;
	// Initialize python
	Py_Initialize();
	// Register the api wrappers
	(void) Py_InitModule(WIPE_MODULE_NAME, WipeMethods);
	// Redirect python's stdout and stderr output into debugger (to see exceptions etc...)
	PyRun_SimpleString(
		"import wipe\n"
		"import sys\n"
		"class StreamHook(object):\n"
		"\tdef write(self, str):\n"
		"\t\twipe.dprintf(str)\n"
		"sys.stdout = StreamHook()\n"
		"sys.stderr = StreamHook()\n");
}


DECLARE_API64(execpy)
{
	if (PyRun_SimpleString(args))
	{
		dprintf("Error while running %s\n", args);
		PyErr_Print();
	}
	dprintf("finished.\n");
}
