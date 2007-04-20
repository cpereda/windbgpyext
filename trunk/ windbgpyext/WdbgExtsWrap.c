/*** Includes ****************************************************/
#include "common.h"

/*** definitions *************************************************/
#define SIGN_EXTEND( x ) (ULONG64)(LONG)( x )

typedef ULONG(*PFN_MEMORYREADFUNC)(ULONG, PVOID, ULONG, PULONG);
typedef ULONG(*PFN_MEMORYWRITEFUNC)(ULONG, PVOID, ULONG, PULONG);

/*** Implementation **********************************************/
PyObject * wipe_dprintf(PyObject * self, PyObject * args)
{
    char * format;

    if (!PyArg_ParseTuple(args, "s", &format))
	{
        return NULL;
	}

    dprintf(format);
    
	Py_INCREF(Py_None);
    return Py_None;
}

PyObject * wipe_CheckControlC(PyObject * self, PyObject * args)
{
    if (!PyArg_ParseTuple(args, ""))
	{
        return NULL;
	}

    return Py_BuildValue("k", CheckControlC());
}


PyObject * wipe_Disasm(PyObject *self, PyObject *args)
{
	PULONG pulOffset;
	CHAR caBuf[BUFSIZE] = {0,};
	ULONG ulShowEffectiveAddress;

    if (!PyArg_ParseTuple(args, "kk", &pulOffset, &ulShowEffectiveAddress))
	{
        return NULL;
	}

	//FIXME
    if (Disasm(pulOffset, caBuf, ulShowEffectiveAddress))
	{
		return Py_BuildValue("sk", caBuf);
	}
	else
	{
		Py_INCREF(Py_None);
		return Py_None;
	}
}

PyObject * wipe_GetExpression(PyObject * self, PyObject * args)
{
	LPCSTR szExpr;

	if (!PyArg_ParseTuple(args, "s", &szExpr))
	{
		return NULL;
	}

	return Py_BuildValue("k", GetExpression(szExpr));
}

PyObject * wipe_GetKdContext(PyObject * self, PyObject * args)
{
	PROCESSORINFO tInfo = {0,};

	if (!PyArg_ParseTuple(args, ""))
	{
		return NULL;
	}

	GetKdContext(&tInfo);

	return Py_BuildValue("HH", tInfo.Processor, tInfo.NumberProcessors);
}

PyObject * wipe_ReadMemory(PyObject * self, PyObject * args)
{
	ULONG ulOffset;
	ULONG ulSize;
	PBYTE pbBuf;
	ULONG cbBytesRead;
	PyObject * ptRet = NULL;

	if (!PyArg_ParseTuple(args, "kk", &ulOffset, &ulSize))
	{
		return NULL;
	}

	pbBuf = HeapAlloc(GetProcessHeap(), 0, ulSize);
	if (NULL == pbBuf)
	{
		// need to raise proper error
		return NULL;
	}

	if (!ReadMemory(SIGN_EXTEND(ulOffset), pbBuf, ulSize, &cbBytesRead))
	{
		goto lbl_Cleanup;
	}
	
	ptRet  = Py_BuildValue("s#", pbBuf, cbBytesRead);

lbl_Cleanup:
	if (NULL != pbBuf)
	{
		HeapFree(GetProcessHeap(), 0, pbBuf);
		pbBuf = NULL;
	}

	return ptRet ;
}

PyObject * wipe_WriteMemory(PyObject * self, PyObject * args)
{
	ULONG ulOffset;
	PBYTE pbBuf;
	ULONG cbBufSize;
	ULONG cbBytesWritten = 0;

	if (!PyArg_ParseTuple(args, "ks#", &ulOffset, &pbBuf, &cbBufSize))
	{
		return NULL;
	}

	if (!WriteMemory(SIGN_EXTEND(ulOffset), pbBuf, cbBufSize, &cbBytesWritten))
	{
		return Py_BuildValue("k", 0);
	}
	else
	{
		return Py_BuildValue("k", cbBytesWritten);
	}
}

PyObject * wipe_ReadMsr(PyObject * self, PyObject * args)
{
	ULONG ulMsr;
	ULONGLONG tValue;

	if (!PyArg_ParseTuple(args, "k", &ulMsr))
	{
		return NULL;
	}

	ReadMsr(ulMsr, &tValue);

	return Py_BuildValue("K", tValue);
}

PyObject * wipe_WriteMsr(PyObject * self, PyObject * args)
{
	ULONG ulMsr;
	ULONGLONG tValue;

	if (!PyArg_ParseTuple(args, "kK", &ulMsr, &tValue))
	{
		return NULL;
	}

	WriteMsr(ulMsr, tValue);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject * wipe_ReadPhysical(PyObject * self, PyObject * args)
{
	ULONG ulOffset;
	ULONG ulSize;
	PBYTE pbBuf;
	ULONG cbBytesRead;
	PyObject * ptRet = NULL;

	if (!PyArg_ParseTuple(args, "kk", &ulOffset, &ulSize))
	{
		return NULL;
	}

	pbBuf = HeapAlloc(GetProcessHeap(), 0, ulSize);
	if (NULL == pbBuf)
	{
		// need to raise proper error
		return NULL;
	}

	ReadPhysical(SIGN_EXTEND(ulOffset), pbBuf, ulSize, &cbBytesRead);
	
	ptRet  = Py_BuildValue("s#", pbBuf, cbBytesRead);

	HeapFree(GetProcessHeap(), 0, pbBuf);
	pbBuf = NULL;

	return ptRet ;

}

PyObject * wipe_WritePhysical(PyObject * self, PyObject * args)
{
	ULONG ulOffset;
	PBYTE pbBuf;
	ULONG cbBufSize;
	ULONG cbBytesWritten = 0;

	if (!PyArg_ParseTuple(args, "ks#", &ulOffset, &pbBuf, &cbBufSize))
	{
		return NULL;
	}

	WritePhysical(SIGN_EXTEND(ulOffset), pbBuf, cbBufSize, &cbBytesWritten);
	return Py_BuildValue("k", cbBytesWritten);
}

PyObject * wipe_GetSymbol(PyObject * self, PyObject * args)
{
	PVOID pOffset = NULL;
	BYTE baBuf[BUFSIZE] = {0,};
	ULONG ulDisplacement;

	if (!PyArg_ParseTuple(args, "k", &pOffset))
	{
		return NULL;
	}

	GetSymbol(pOffset, baBuf, &ulDisplacement);

	return Py_BuildValue("sk", baBuf, ulDisplacement);
}

PyObject * wipe_GetContext(PyObject * self, PyObject * args)
{
	ULONG ulTarget;
	CONTEXT tContext;
	
	if (!PyArg_ParseTuple(args, "k", &ulTarget))
	{
		return NULL;
	}

	if (!GetContext(ulTarget, &tContext, sizeof(tContext)))
	{
		Py_INCREF(Py_None);
		return Py_None;
	}

	return Py_BuildValue("s#", &tContext, sizeof(tContext));
}

PyObject * wipe_SetContext(PyObject * self, PyObject * args)
{
	ULONG ulTarget;
	PBYTE pbContext;
	ULONG cbContextSize;
	
	if (!PyArg_ParseTuple(args, "ks#", &ulTarget, &pbContext, &cbContextSize))
	{
		return NULL;
	}

	// Add exception on failure later
	if ((cbContextSize != sizeof(CONTEXT)) || 
		(!SetContext(ulTarget, (PCONTEXT)pbContext, cbContextSize)))
	{
		Py_INCREF(Py_False);
		return Py_False;
	}
	else
	{
		Py_INCREF(Py_True);
		return Py_True;
	}
}
