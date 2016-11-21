#include "pin.H"
#include<iostream>
#include<fstream>
#include<string.h>
#include<map>

/* ========================================================================================= */
/* Names of Malloc and Free */
/* ========================================================================================= */

#define MALLOC "malloc"
#define CALLOC "calloc"
#define FREE "free"
#define FGETS "fgets"
#define READ "read"
#define MEMCPY "memcpy"
#define STRNCPY "strncpy"

/* ========================================================================================= */
/* Global Variables */
/* ========================================================================================= */

std::ofstream TraceFile;
std::map<VOID *,INT32> in_use;
std::map<VOID *,INT32> freed;
INT32 malloc_size=0;

/* ========================================================================================= */
/* Commandline switches */
/* ========================================================================================= */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
   "o", "heap_trace.out", "specify trace file name");

/* ========================================================================================= */
/* Print Help */
/* ========================================================================================= */

INT32 Usage()
{
    cerr <<
        "This tool produces a trace of calls to gets and fgets.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

bool isMain(ADDRINT ret)
{
    PIN_LockClient();
    IMG im = IMG_FindByAddress(ret);
    PIN_UnlockClient();
    int inMain = IMG_Valid(im) ? IMG_IsMainExecutable(im) : 0;
    return inMain;
}

VOID malloc_before(INT32 size)
{
	malloc_size = size;
}

VOID malloc_after(VOID *chunk)
{
	TraceFile << "malloc(" << malloc_size << ") returns " << chunk << endl;
	if ( in_use.count(chunk) )
	{
		cout << "\n[+][+]Chunk "<< chunk <<" allocated more than once" << endl;
	}

	in_use[chunk] = malloc_size;
}

VOID calloc_before(INT32 size)
{
	malloc_size = size;
}

VOID calloc_after(VOID *chunk)
{
	TraceFile << "calloc(" << malloc_size << ") returns " << chunk << endl;
	if ( in_use.count( chunk))
	{
		cout << "\n[+][+]Chunk "<< chunk <<" allocated more than once" << endl;
	}
	
	in_use[chunk] = malloc_size;
}

VOID free_chunk(VOID *chunk)
{
	TraceFile << "free(" << chunk << ")" << endl;
	if ( freed.count(chunk) )
	{
		cout << "\n[+][+]Chunk " << chunk << " freed more than once" << endl;
	}
	freed[chunk] = in_use[chunk];
	in_use.erase(chunk);
}

VOID check_write(VOID *buffer, INT32 size)
{
	map<VOID *,INT32>::iterator it;	
	
	if ( freed.count(buffer) )
	{
		cout << "\n[+][+]Reading input to freed chunk " << buffer << endl;
		
		if ( freed[buffer] < size )
		{
			cout << "\n[+][+]Overflow while writing " << size << " bytes to ";
			cout << buffer << endl;
		}
	}
	
	else 
	{
 		for ( it = freed.begin(); it != freed.end(); it++)
		{
			if ( buffer > it->first && (int *)buffer < (int *)it->first + it->second )
			{
				cout << "\n[+][+]Reading input to freed chunk " << buffer << endl;
				
				if ( ( (int *) it->first + it->second - (int *) buffer ) < size )
                                {
                                        cout << "\n[+][+]Overflow while writing " << size;
                                        cout  << " bytes to " << it->first<< endl;
                                }
			}
			break;
		}
	}

	if ( in_use.count(buffer) )
	{
		if ( in_use[buffer] < size )
		{
			cout << "\n[+][+]Overflow while writing " << size  << " bytes to "; 
			cout << buffer << " of size " << in_use[buffer] << endl;
			return;
		}
		return;
	}
		
	else
	{	
		for ( it = in_use.begin(); it!=in_use.end(); it++)
		{
			if ( buffer > it->first && (int *) buffer < (int *) it->first + it->second )
			{
				if ( ( (int *) it->first + it->second - (int *) buffer ) < size )
				{
					cout << "\n[+][+]Overflow while writing " << size;
					cout  << " bytes to " << it->first<< endl;
				}
				return;
			}
		}
	}
}

VOID fgets_call(VOID *buffer, INT32 size)
{
        TraceFile << "fgets(" << buffer << " , " << size << " , stdin);" << endl;
        check_write(buffer,size);
}

VOID read_call(VOID *buffer, INT32 size)
{
        TraceFile << "read(0" << buffer << " , " << size << ")" << endl;
        check_write(buffer,size);
}

VOID memcpy_call(VOID *buffer, INT32 size)
{
	TraceFile << "memcpy(" << buffer << " , " << size << ")" << endl;
	check_write(buffer,size);
}

VOID strncpy_call(VOID *buffer, INT32 size)
{
	TraceFile << "strncpy(" << buffer << " , " << size << ")" << endl;
	check_write(buffer,size);
}

/* ===================================================================== */

VOID Image(IMG img,VOID *v)
{
    	RTN rtn = RTN_FindByName(img, MALLOC);
    	if (RTN_Valid(rtn))
    	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)malloc_before,
		IARG_G_ARG0_CALLEE,IARG_END);
		RTN_InsertCall(rtn,IPOINT_AFTER,(AFUNPTR)malloc_after,IARG_G_RESULT0,IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, CALLOC);
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)calloc_before,
		IARG_G_ARG0_CALLEE,IARG_END);
		RTN_InsertCall(rtn,IPOINT_AFTER,(AFUNPTR)calloc_after,IARG_G_RESULT0,IARG_END);
		RTN_Close(rtn);
	}
	
	rtn = RTN_FindByName(img,FREE);
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)free_chunk,IARG_G_ARG0_CALLEE,IARG_END);
		RTN_Close(rtn);
	}
	
	rtn = RTN_FindByName(img,FGETS);
	if (RTN_Valid(rtn) )
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)fgets_call,IARG_G_ARG0_CALLEE,
		IARG_G_ARG1_CALLEE,IARG_END);
		RTN_Close(rtn);
	}
	
	rtn = RTN_FindByName(img,READ);
	if (RTN_Valid(rtn) )
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)read_call,IARG_G_ARG1_CALLEE,
		IARG_G_ARG2_CALLEE,IARG_END);
		RTN_Close(rtn);
	}
	
	rtn = RTN_FindByName(img,MEMCPY);
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)memcpy_call,IARG_G_ARG1_CALLEE,
		IARG_G_ARG3_CALLEE,IARG_END);
		RTN_Close(rtn);
	}
	
	rtn = RTN_FindByName(img,STRNCPY);
	if(RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)strncpy_call,IARG_G_ARG1_CALLEE,
		IARG_G_ARG3_CALLEE,IARG_END);
		RTN_Close(rtn);
	}
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	TraceFile.close();
}

/* ===================================================================== */

int main(int argc, char *argv[])
{
	PIN_InitSymbols();
	
	if ( PIN_Init(argc,argv) )
	{
		return Usage();
	}
	
	TraceFile.open(KnobOutputFile.Value().c_str() );
	
	TraceFile << hex;
	TraceFile.setf(ios::showbase);
	
	cout << hex;
	cout.setf(ios::showbase);
	
	IMG_AddInstrumentFunction(Image, 0);
	PIN_AddFiniFunction(Fini, 0);
	
	PIN_StartProgram();
	
	return 0;
}

/* ===================================================================== */
