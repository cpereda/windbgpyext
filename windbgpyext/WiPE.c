/*** Includes ****************************************************/

#include "common.h"
#include "WdbgExtsWrap.h"

/*** definitions *************************************************/

#define WIPE_VERSION_MAJOR (5)
#define WIPE_VERSION_MINOR (5)

/*** Globals *****************************************************/

static PyMethodDef taWipeMethods[] = {
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
	{"StackTrace", wipe_StackTrace, METH_VARARGS, "Extracts the stackframes"},
    {NULL, NULL, 0, NULL}
};

HMODULE g_hModule = NULL;

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
			g_hModule = hModule;
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
	(void) Py_InitModule(WIPE_MODULE_NAME, taWipeMethods);
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
}

DECLARE_API64(expyscript)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	CHAR szPath[MAX_PATH] = {0,};
	PCHAR pcLastSlash = NULL;
	DWORD cbFileSize = 0;
	LPSTR szScriptContent = NULL;
	DWORD cbBytesRead = 0;
	FILE * ptFile = NULL;
	INT i;

	if (0 == GetModuleFileName(g_hModule, szPath, sizeof(szPath) - 1))
	{
		dprintf("failed\n");
		return;
	}

	pcLastSlash = strrchr(szPath ,'\\');
	if (pcLastSlash)
	{
		strncpy(pcLastSlash + 1, args, sizeof(szPath) - 1 - (pcLastSlash + 1 - szPath));
	}
	else
	{
		strncpy(szPath, args, sizeof(szPath) - 1);
	}

	/*
	ptFile = fopen(szPath, "r");
	if (NULL == ptFile)
	{
		dprintf("Cannot open file %s. (%d)\n", args, GetLastError());
		return;
	}

	PyRun_SimpleFile(ptFile, args);
	fclose(ptFile);
	*/

	// This is a workaround since SimpleFile doesnt work for some reason
	hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		dprintf("Cannot open file %s. (%d)\n", args, GetLastError());
		goto lbl_cleanup;
	}
	cbFileSize = GetFileSize(hFile, NULL);

	if (0 >= cbFileSize)
	{
		goto lbl_cleanup;
	}

	szScriptContent = HeapAlloc(GetProcessHeap(), 0, cbFileSize + 1);
	if (NULL == szScriptContent)
	{
		dprintf("Cannot allocate memory\n");
		goto lbl_cleanup;
	}

	szScriptContent[cbFileSize] = '\0';

	if (!ReadFile(hFile, szScriptContent, cbFileSize, &cbBytesRead, NULL) ||
		(cbFileSize != cbBytesRead))
	{
		dprintf("Read failed\n");
		goto lbl_cleanup;
	}

	for (i = 0; i <cbFileSize; i++)
	{
		if ('\r' == szScriptContent[i])
		{
			szScriptContent[i] = ' ';
		}
	}

	if (PyRun_SimpleString(szScriptContent))
	{
		dprintf("Error while running %s\n", args);
		PyErr_Print();
	}

lbl_cleanup:

	if (INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	if (NULL != szScriptContent)
	{
		HeapFree(GetProcessHeap(), 0, szScriptContent);
		szScriptContent = NULL;
	}
}

