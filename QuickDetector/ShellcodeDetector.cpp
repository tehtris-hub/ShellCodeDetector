#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>

namespace WINDOWS {
    #include <windows.h>
    #include <memoryapi.h>
};

#define FLAG_EXECUTED   1
#define FLAG_WRITTEN    2
#define FLAG_READ       4

#define LOG_ERROR       0
#define LOG_WARNING     1
#define LOG_INFO        2

#define Log(logentry, level) do {Logger(__FILE__, __LINE__, logentry, level);} while(0)

typedef struct _TRACEACCESS {
    UINT32 access_type;
    ADDRINT membase;
} TRACEACCESS, *PTRACEACCESS;

typedef struct _TRACE {
    ADDRINT address;
    USIZE length;
    size_t accessnb;
    PTRACEACCESS access;
} *PTRACE;

typedef struct _MEMACCESS {
    size_t tracenb;
    PTRACE trace;
} MEMACCESS, PMEMACCESS;

MEMACCESS memaccess = {0};

std::map<UINT32, WINDOWS::BYTE *> imagemap;
std::vector<UINT32> SMCimagelist;
std::map<UINT32, std::string> logverb;
std::string outputdir;

BOOL entrypoint_reached = FALSE;

UINT32 startdate = 0;
PIN_MUTEX shellcodelock, PElock, loggerlock, accesslock;
std::ofstream TraceFile;

KNOB<std::string> KnobOutputDir(KNOB_MODE_WRITEONCE, "pintool", "o", "%temp%\\ShellcodeDetector", "Log file location");
KNOB<UINT32> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "d", "2", "Log Level 0=error, 1=warning, 2=info");
KNOB<UINT32> KnobTimeOut(KNOB_MODE_WRITEONCE, "pintool", "f", "600", "Max timeout (s)");

void Logger(std::string filename, uint32_t linenb, std::string logentry, UINT32 level);

/*
 * @brief: Logger
 * @param filename: The filename in source code from where the log is raised
 * @param linenb: The line number in source code from where the log is raised
 * @param logentry: text file
 * @param level: The log level (LOG_INFO, LOG_WARNING, LOG_ERROR)
 */
void Logger(std::string filename, uint32_t linenb, std::string logentry, UINT32 level)
{
    PIN_MutexLock(&loggerlock);
    std::string line = "[" + logverb[level] + "] " + filename + ":" + decstr(linenb) + "    " + logentry;
    TraceFile << line << std::endl << std::flush;
    if(level > KnobDebug.Value()) {
        PIN_MutexUnlock(&loggerlock);
        return;
    }
    if(level == LOG_ERROR) {
        std::cerr << line << std::endl << std::flush;
    } else {
        std::cout << line << std::endl << std::flush;
    }
    PIN_MutexUnlock(&loggerlock);
}

INT32 Usage()
{
    std::cerr << KNOB_BASE::StringKnobSummary();
    std::cerr << std::endl;
    return -1;
}

/*
 * @brief: Safely dump trace from memory to .trc file in KnobOutputDir location
 * @param addr: The address of the suspected PE
 * @param machine: machine type as given in the IMAGE_OPTIONAL_HEADER
 */
void DumpTrace(ADDRINT addr)
{
    for (size_t traceindex = 0; traceindex < memaccess.tracenb; traceindex++) {
        for (size_t accessindex = 0; accessindex < memaccess.trace[traceindex].accessnb; accessindex++) {
            if (memaccess.trace[traceindex].access[accessindex].membase == addr &&
                memaccess.trace[traceindex].access[accessindex].access_type == FLAG_WRITTEN) {
                //Found a trace matching the access
                USIZE length = memaccess.trace[traceindex].length;
                ADDRINT traceaddr = memaccess.trace[traceindex].address;
                //find the image related to the trace
                std::string outputfilename = outputdir + "\\" + hexstr(PIN_GetPid()) + "_" + StringFromAddrint(traceaddr) + ".trc";
                std::ifstream test(outputfilename.c_str());
                if (test.is_open()) { //Already written
                    test.close();
                    return;
                }
                PIN_LockClient();
                IMG image = IMG_FindByAddress(traceaddr);
                PIN_UnlockClient();
                if (IMG_Valid(image)) {
                    Log("Found obfuscation routine at: " + hexstr(traceaddr) + " (" + IMG_Name(image) + "+" + hexstr(traceaddr - IMG_LowAddress(image)) + ")", LOG_INFO);
                }
                Log("Dumping trace into: " + outputfilename, LOG_INFO);
                std::ofstream outputfile(outputfilename.c_str(), std::ios::binary);
                if (!outputfile.is_open()) {
                    Log("Failed to commit the trace", LOG_ERROR);
                }
                void* buffer = malloc(length);
                if (!buffer) {
                    Log("Failed to allocate", LOG_ERROR);
                    return;
                }
                memset(buffer, '\x00', length);
                PIN_SafeCopy(buffer, (void*)traceaddr, length);// Avoid memory violation
                outputfile.write((char*)buffer, length);
                free(buffer);
                outputfile.close();
                return;
            }
        }
    }
    Log("Unable to find the trace associated with: " + hexstr(addr), LOG_ERROR);
}

/*
 * @brief: Safely dump PE from memory to .dll or .exe file in KnobOutputDir location
 * @param addr: The address of the suspected PE
 * @param machine: machine type as given in the IMAGE_OPTIONAL_HEADER
 */
void DumpPE(void *addr, UINT16 machine)
{
    WINDOWS::PIMAGE_DOS_HEADER dosheader = (WINDOWS::PIMAGE_DOS_HEADER)addr;
    size_t headersize = dosheader->e_lfanew;
    size_t sectionnb = 0;

    std::string outputfilename = outputdir + "\\" + hexstr(PIN_GetPid()) + "_" + StringFromAddrint((ADDRINT)addr);
    PIN_MutexLock(&PElock);
    if(machine == 0x14c) {
        WINDOWS::PIMAGE_NT_HEADERS32 ntheader = (WINDOWS::PIMAGE_NT_HEADERS32)((ADDRINT)addr + dosheader->e_lfanew);
        headersize += sizeof(WINDOWS::IMAGE_NT_HEADERS32);
        sectionnb = ntheader->FileHeader.NumberOfSections;
        if(ntheader->FileHeader.Characteristics && 0x2000) {
            outputfilename += ".dll";
        } else {
            outputfilename += ".exe";
        }
    } else if(machine == 0x8664) {
        WINDOWS::PIMAGE_NT_HEADERS64 ntheader = (WINDOWS::PIMAGE_NT_HEADERS64)((ADDRINT)addr + dosheader->e_lfanew);
        headersize += sizeof(WINDOWS::IMAGE_NT_HEADERS64);
        sectionnb = ntheader->FileHeader.NumberOfSections;
        if(ntheader->FileHeader.Characteristics && 0x2000) {
            outputfilename += ".dll";
        } else {
            outputfilename += ".exe";
        }
    } else {
        Log("PE: Unknown file format", LOG_ERROR);
        PIN_MutexUnlock(&PElock);
        return;
    }
    std::ifstream test(outputfilename.c_str());
    if(test.is_open()) {
        //Already logged
        test.close();
        PIN_MutexUnlock(&PElock);
        return;
    }
    DumpTrace((ADDRINT)addr);
    std::ofstream outputfile(outputfilename.c_str(), std::ios::binary);
    if(!outputfile.is_open()) {
        Log("Failed to open file: " + outputfilename + " (" + decstr((UINT32)WINDOWS::GetLastError()) + ")", LOG_ERROR);
        PIN_MutexUnlock(&PElock);
        return;
    }
    Log("Dumping PE into: " + outputfilename, LOG_INFO);
    // Copy header
    outputfile.write((char *)addr, headersize + sectionnb * sizeof(WINDOWS::IMAGE_SECTION_HEADER));
    for(size_t i=0; i<sectionnb; i++) {
        WINDOWS::PIMAGE_SECTION_HEADER section = (WINDOWS::PIMAGE_SECTION_HEADER)((ADDRINT)addr + headersize + i * sizeof(WINDOWS::IMAGE_SECTION_HEADER));
        void *sectionbuffer = malloc(section->SizeOfRawData);
        if(!sectionbuffer) {
            Log("Failed to allocate buffer: file truncated", LOG_ERROR);
            outputfile.close();
            PIN_MutexUnlock(&PElock);
            return;
        }
        memset(sectionbuffer, '\x00', section->SizeOfRawData);
        PIN_SafeCopy(sectionbuffer, (void *)((ADDRINT)addr + section->VirtualAddress), section->SizeOfRawData);// Avoid memory violation
        outputfile.seekp(section->PointerToRawData);
        outputfile.write((char *)sectionbuffer, section->SizeOfRawData);
        free(sectionbuffer);
    }
    Log("Dumped: " + decstr(outputfile.tellp()) + " bytes", LOG_INFO);
    outputfile.close();
    PIN_MutexUnlock(&PElock);
}

/*
 * @brief: Safely dump Shellcode from memory to .bin file in KnobOutputDir location
 * @param traceaddr: The address of the suspected shellcode
 */
void DumpShellCode(void *traceaddr)
{
    PIN_MutexLock(&shellcodelock);
    WINDOWS::MEMORY_BASIC_INFORMATION meminfo = {0};
    WINDOWS::SIZE_T returnsize;
    if(!WINDOWS::VirtualQuery(traceaddr, &meminfo, sizeof(meminfo))) {
        Log("ERROR: Failed to Query memory at: " + StringFromAddrint((ADDRINT)traceaddr), LOG_ERROR);
        PIN_MutexUnlock(&shellcodelock);
        return;
    }
    WINDOWS::PIMAGE_DOS_HEADER dosheader = (WINDOWS::PIMAGE_DOS_HEADER)meminfo.AllocationBase;
    WINDOWS::PIMAGE_NT_HEADERS32 ntheader = (WINDOWS::PIMAGE_NT_HEADERS32)((ADDRINT)meminfo.AllocationBase + dosheader->e_lfanew);
    //Check if the shellcode looks lie a pe file.
    if(meminfo.RegionSize > sizeof(WINDOWS::IMAGE_DOS_HEADER) && dosheader->e_magic == 0x5a4d &&
        meminfo.RegionSize > sizeof(WINDOWS::PIMAGE_NT_HEADERS64) + dosheader->e_lfanew + ntheader->FileHeader.NumberOfSections * sizeof(WINDOWS::IMAGE_SECTION_HEADER) &&
        ntheader->Signature == 0x4550) {
            DumpPE((void *)meminfo.AllocationBase, (UINT16)ntheader->FileHeader.Machine);
    } else {
        std::string outputfilename = outputdir + "\\" + hexstr(PIN_GetPid()) + "_" + StringFromAddrint((ADDRINT)meminfo.AllocationBase) + ".bin";
        std::ifstream test(outputfilename.c_str());
        if(test.is_open()) {
            //Already dumped
            test.close();
        } else {
            DumpTrace((ADDRINT)meminfo.AllocationBase);
            Log("Dumping ShellCode: " + outputfilename + " ep=" + StringFromAddrint((ADDRINT)traceaddr - (ADDRINT)meminfo.AllocationBase) + " size=" + hexstr((size_t)meminfo.RegionSize), LOG_INFO);
            if((ADDRINT)traceaddr - (ADDRINT)meminfo.AllocationBase > (size_t)meminfo.RegionSize) {
                Log("Entry point outside memory space", LOG_ERROR);
            }
            std::ofstream shellcode(outputfilename.c_str(), std::ios::binary);
            if(shellcode.is_open()) {
                WINDOWS::BYTE *shellcodebuffer = (WINDOWS::BYTE *)malloc(meminfo.RegionSize);
                if(shellcodebuffer) {
                    memset(shellcodebuffer, '\x00', meminfo.RegionSize);
                    PIN_SafeCopy(shellcodebuffer, meminfo.AllocationBase, meminfo.RegionSize);// Avoid memory violation
                    shellcode.write((char *)shellcodebuffer, meminfo.RegionSize);
                    free(shellcodebuffer);
                } else {
                    Log("Cannot allocate enough memory to dump the shellcode", LOG_ERROR);
                }
                Log("Dumped: " + decstr(shellcode.tellp()) + " bytes", LOG_INFO);
                shellcode.close();
            } else {
                Log("Failed to dump: " + decstr((UINT32)WINDOWS::GetLastError()), LOG_ERROR);
            }
        }
    }
    PIN_MutexUnlock(&shellcodelock);
}

/*
 * @brief: Populate a new Memory Access. Create if not exists
 * @param trace: A pointer to _TRACE struct from which the call is performed
 * @param addr: The address of target
 * @param operation: One of FLAG_WRITTEN, FLAG_READ, FLAG_EXECUTED
 */
VOID AddAccess(PTRACE trace, ADDRINT addr, UINT32 operation)
{
    WINDOWS::MEMORY_BASIC_INFORMATION meminfo = {0};
    if(!WINDOWS::VirtualQuery((void *)addr, &meminfo, sizeof(meminfo))) {
        Log("ERROR: Failed to Query memory at: " + StringFromAddrint((ADDRINT)addr), LOG_ERROR);
        return;
    }
    for(size_t i=0; i<trace->accessnb; i++) {
        if(trace->access[i].membase == (ADDRINT)meminfo.AllocationBase) {
            trace->access[i].access_type |= operation; //Upgrade operation
            return;
        }
    }
    //Create a new access
    trace->access = (PTRACEACCESS)realloc(trace->access, (trace->accessnb + 1) * sizeof(TRACEACCESS));
    if(!trace->access) {
        Log("Failed to allocate", LOG_ERROR);
        return;
    }
    trace->access[trace->accessnb].access_type = operation;
    trace->access[trace->accessnb].membase = (ADDRINT)meminfo.AllocationBase;
    trace->accessnb++;
}

/*
 * @brief: Populate a trace. Create if not exists
 * #param TRACEADDR: The address of the trace which performs the write operation
 * @param addr: The address of memory written
 * @param size: The size of memory written
 * @param trace_length: The length of the trace which performs the write operation
 */
PTRACE GetCurrTrace(ADDRINT TRACEADDR, UINT32 trace_length)
{
    // find existing trace
    for(size_t i=0; i<memaccess.tracenb; i++) {
        if(memaccess.trace[i].address == TRACEADDR) {
            return &memaccess.trace[i];
        }
    }
    //create a new trace
    memaccess.trace = (PTRACE)realloc(memaccess.trace, (memaccess.tracenb + 1) * sizeof(_TRACE));
    if(!memaccess.trace) {
        Log("Failed to allocate", LOG_ERROR);
        return NULL;
    }
    memaccess.trace[memaccess.tracenb].address = TRACEADDR;
    memaccess.trace[memaccess.tracenb].length = trace_length;
    memaccess.trace[memaccess.tracenb].accessnb = 0;
    return &memaccess.trace[memaccess.tracenb++];
}

/*
 * @brief: Called each time memory is written
 * @param TRACEADDR: The address of the trace which performs the write operation
 * @param addr: The address of memory written
 * @param size: The size of memory written
 * @param trace_length: The length of the trace which performs the write operation
 */
VOID RecordMemWrite(ADDRINT TRACEADDR, VOID * addr, UINT32 size, UINT32 trace_length)
{
    PIN_MutexLock(&accesslock);
    PTRACE currtrace = GetCurrTrace(TRACEADDR, trace_length);
    if(!currtrace) {
        Log("Unable to find current trace", LOG_ERROR);
        PIN_MutexUnlock(&accesslock);
        return;
    }
    //Do not bother size, should not jump over memory pages
    AddAccess(currtrace, (ADDRINT)addr, FLAG_WRITTEN);
    PIN_MutexUnlock(&accesslock);
    return;
}

/*
 * @brief: Trace callback
 * @param trace: Pin trace
 * @param v: NULL
 */
void Trace(TRACE trace, void *v)
{
    if(time(NULL) - startdate > KnobTimeOut.Value()) {
        Log("Timeout reached, application killed: " + decstr(time(NULL)) + " " + decstr(startdate) + "  " + decstr(KnobTimeOut.Value()), LOG_WARNING);
        PIN_ExitProcess(0);
        return;
    }
    ADDRINT address = TRACE_Address(trace);
    USIZE trace_length = TRACE_Size(trace);
    PIN_LockClient();
    IMG img = IMG_FindByAddress(address);
    PIN_UnlockClient();
    //Wait until entry point is reached
    if(IMG_Valid(img)) {
        if(!entrypoint_reached && IMG_IsMainExecutable(img)) {
            entrypoint_reached = TRUE;
            Log("Entrypoint Reached", LOG_INFO);
        }
        if (!entrypoint_reached) { //Do not log if executable have not been executed yet
            return;
        }
    } else { //img not valid
        if(entrypoint_reached) {
            DumpShellCode((void *)address);
        }
        return;
    }
    UINT32 id = IMG_Id(img);
    if(imagemap.find(id) != imagemap.end()) {
        if(imagemap[id][address - IMG_StartAddress(img)] & FLAG_WRITTEN ) {
            if(std::find(SMCimagelist.begin(), SMCimagelist.end(), id) == SMCimagelist.end()) {
                SMCimagelist.push_back(id);
                Log("SMC found: " + IMG_Name(img) + "+" + hexstr(address - IMG_StartAddress(img)), LOG_INFO);
                //Dumping the image
                std::string outputfilename = hexstr(PIN_GetPid()) + "_" + StringFromAddrint(IMG_StartAddress(img)) + ".bin";
                Log("Dumping image into: " + outputfilename, LOG_INFO);
                std::ofstream outputfile(outputfilename.c_str(), std::ios::binary);
                if(outputfile.is_open()) {
                    size_t imagesize = IMG_SizeMapped(img);
                    WINDOWS::BYTE *imgbuffer = (WINDOWS::BYTE *)malloc(imagesize);
                    if(imgbuffer) {
                        memset(imgbuffer, '\x00', imagesize);
                        PIN_SafeCopy(imgbuffer, (void *)IMG_StartAddress(img), imagesize);
                        outputfile.write((char *)imgbuffer, imagesize);
                        outputfile.close();
                        free(imgbuffer);
                    } else {
                        Log("Cannot allocate enougn memory to dump image", LOG_ERROR);
                    }
                } else {
                    Log("Cannot open image dump file", LOG_ERROR);
                }
            }
        }
    } else {
        Log("Image not mapped. Should not happen!!", LOG_ERROR);
    }
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            UINT32 memOperands = INS_MemoryOperandCount(ins);
            for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
                if (INS_MemoryOperandIsWritten(ins, memOp) && !INS_OperandIsImplicit(ins, memOp)) {//Discard implicit
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                                                                                IARG_ADDRINT, address, //Root address of the trace
                                                                                IARG_MEMORYOP_EA, memOp,    //Memory operand address
                                                                                IARG_MEMORYWRITE_SIZE,
                                                                                IARG_UINT32, trace_length, IARG_END);
                }
            }
        }
    }
}

/*
 * @brief: Called each time a new dll is loaded
 * @param img: The image
 * @param v: NULL
 */
VOID ImageLoad(IMG img, VOID *v)
{
    PIN_MutexLock(&accesslock);
    UINT32 id = IMG_Id(img);
    size_t imagesize = IMG_SizeMapped(img);
    Log("IMG_LOAD: " + IMG_Name(img) + " addr=" + StringFromAddrint(IMG_StartAddress(img)) + " id=" + decstr(id) + " size=" + hexstr(imagesize), LOG_INFO);
    imagemap[id] = (WINDOWS::BYTE *)malloc(imagesize);
    if(imagemap[id] == NULL) {
        Log("Failed to allocate image", LOG_ERROR);
        PIN_ExitProcess(0);
    } else {
        memset(imagemap[id], '\x00', imagesize);
    }
    PIN_MutexUnlock(&accesslock);
}

/*
 * @brief: Fini callback
 * @param code: The exit code
 * @param v: NULL
 */
VOID Fini(INT32 code, VOID *v)
{
    Log("Done in " + decstr((UINT32)time(NULL) - startdate) + " seconds", LOG_INFO);
    for(const auto &i: imagemap) {
        if(i.second) {
            Log("Freing image: " + decstr(i.first), LOG_INFO);
            free(i.second);
        }
    }
}

int  main(int argc, char *argv[])
{
    //Visual studio with pin does not support static array inizialization.
    logverb.insert(std::pair<UINT32, std::string>(LOG_ERROR, "ERROR"));
    logverb.insert(std::pair<UINT32, std::string>(LOG_WARNING, "WARNING"));
    logverb.insert(std::pair<UINT32, std::string>(LOG_INFO, "INFO"));
    Log("Starting main", LOG_INFO);
    if( PIN_Init(argc,argv) ) {
        Log("Bad usage", LOG_ERROR);
        return Usage();
    }
    if(!PIN_MutexInit(&shellcodelock) || !PIN_MutexInit(&PElock) || !PIN_MutexInit(&loggerlock) || !PIN_MutexInit(&accesslock)) {
        Log("Failed to init mutex", LOG_ERROR);
        return 1;
    }
    char _outputdir[MAX_PATH] = {0};
    if(WINDOWS::ExpandEnvironmentStringsA(KnobOutputDir.Value().c_str(), _outputdir, sizeof(_outputdir)) == 0) {
        Log("Failed to resolve path: " + KnobOutputDir.Value(), LOG_ERROR);
        return 1;
    }
    outputdir = std::string(_outputdir);
    if(WINDOWS::CreateDirectory(outputdir.c_str(), NULL) == ERROR_PATH_NOT_FOUND) {
        Log("Failed to create output dir", LOG_ERROR);
        return 1;
    }
    std::string logfilename = outputdir + "\\trace.log";
    TraceFile.open(logfilename.c_str());
    startdate = time(NULL);


    TRACE_AddInstrumentFunction(Trace, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    Log("Starting program: pid=" + decstr(PIN_GetPid()), LOG_INFO);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
