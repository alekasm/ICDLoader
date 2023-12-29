#include <Windows.h>
#include <conio.h>
#include <iostream>
#include <string.h>


//void* FileMapData = (void*)0x431860;
const int FILEMAP_SIZE = 0xC8;
//This data is always available
const char FileMapData[FILEMAP_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x64, 0x08, 0xA1, 0x8F, 0x64, 0x08, 0xA1, 0x8F,
	0xDC, 0x05, 0xA1, 0x8F, 0xDC, 0x05, 0xA1, 0x8F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//Function exists before StartGame at 0x4079A0
const int INJECTED_FUNCWITHSTACK_SIZE = 0x80;
//This data is only available after decryption
const char InjectedFuncWithStack[INJECTED_FUNCWITHSTACK_SIZE] = {
	0x00, 0x00, 0x00, 0x00, //0x00 - 0x03: LoadLibraryA Address
	0x00, 0x00, 0x00, 0x00, //0x04 - 0x07: GetProcAddress Address
	0x00, 0x00, 0x00, 0x00, //0x08 - 0x0B: FreeLibrary Address
	0x00, 0x00, 0x00, 0x00, //0x0C - 0x0F: Pointer to Ox7FF052C args
	0x00, 0x00, 0x00, 0x00, //0x10 - 0x23: String "Ox7FF052C"
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00,	
	0x00, 0x00, 0x00, 0x00, //0x24 - 0x37: String "dplayerx"
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x53, //38: push ebx
	0x50, //39: push eax
	0x68, 0xC4, 0x79, 0x40, 0x00, //3A: push 12FF63 <FIXUP>
	0xA1, 0xA0, 0x79, 0x40, 0x00, //3F: mov eax, LoadLibraryA <FIXUP>
	0xFF, 0xD0, //44: call eax
	0x0B, 0xC0, //46: or eax, eax
	0x74, 0x21, //48: jz 12FFAA
	0x50, //4A: push eax
	0x68, 0xB0, 0x79, 0x40, 0x00, //4B: push 12FF4F <FIXUP>
	0x50, //50: push eax
	0xA1, 0xA4, 0x79, 0x40, 0x00, //51: mov eax, GetProcAddress <FIXUP>
	0xFF, 0xD0, //56: call eax
	0x0B, 0xC0, //58: or eax, eax
	0x74, 0x07, //5A: jz 12FFA2
	0x68, 0xAC, 0x79, 0x40, 0x00, //5C: push 12FF4B <FIXUP>
	0xFF, 0xD0, //61: call eax (result of getprocaddress)
	0x58, //63: pop eax
	0xA1, 0xA8, 0x79, 0x40, 0x00, //64: mov eax, FreeLibrary <FIXUP>
	0xFF, 0xD0, //69: call eax
	0x58, //6B: pop eax
	0x5B, //6C: pop ebx
	0x81, 0xC4, 0x00, 0x08, 0x00, 0x00, //6D: add esp, 0x800
	0x53, //73: push ebx
	0xC3, //74: ret

	0x90, 0x90, 0x90, 0x90, //0x75 - 0x7F: padding?
	0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90
};

const int MODIFIED_FUNCWITHSTACK_SIZE = 0x80 + 0x15;
const char ModifiedInjectedFunc[MODIFIED_FUNCWITHSTACK_SIZE] = {
	0x00, 0x00, 0x00, 0x00, //0x00 - 0x03: LoadLibraryA Address
	0x00, 0x00, 0x00, 0x00, //0x04 - 0x07: GetProcAddress Address
	0x00, 0x00, 0x00, 0x00, //0x08 - 0x0B: FreeLibrary Address
	0x00, 0x00, 0x00, 0x00, //0x0C - 0x0F: Pointer to Ox7FF052C args
	0x00, 0x00, 0x00, 0x00, //0x10 - 0x23: String "Ox7FF052C"
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00,	
	0x00, 0x00, 0x00, 0x00, //0x24 - 0x37: String "dplayerx"
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x53, //38: push ebx
	0x50, //39: push eax

	0x6A, 0x10, //3A: push 0x10
	0xB8, 0x46, 0x24, 0x80, 0x7C, //3B: mov eax, 0x7c802446 (Kernel32.Sleep)
	0xFF, 0xD0, //40: call eax
	0xB8, 0x23, 0x31, 0x81, 0x7C, //42: mov eax, 0x7c813123 (Kernel32.IsDebuggerPresent)
	0xFF, 0xD0, //47: call eax
	0x85, 0xC0, //49: test eax, eax
	0x74, 0xEC, //4B: jz 0x3A
	0xCC, //4D: int3


	0x68, 0xC4, 0x79, 0x40, 0x00, //3A: push 12FF63 <FIXUP>
	0xA1, 0xA0, 0x79, 0x40, 0x00, //3F: mov eax, LoadLibraryA <FIXUP>
	0xFF, 0xD0, //44: call eax
	0x0B, 0xC0, //46: or eax, eax
	0x74, 0x21, //48: jz 12FFAA
	0x50, //4A: push eax
	0x68, 0xB0, 0x79, 0x40, 0x00, //4B: push 12FF4F <FIXUP>
	0x50, //50: push eax
	0xA1, 0xA4, 0x79, 0x40, 0x00, //51: mov eax, GetProcAddress <FIXUP>
	0xFF, 0xD0, //56: call eax
	0x0B, 0xC0, //58: or eax, eax
	0x74, 0x07, //5A: jz 12FFA2
	0x68, 0xAC, 0x79, 0x40, 0x00, //5C: push 12FF4B <FIXUP>
	0xFF, 0xD0, //61: call eax (result of getprocaddress)
	0x58, //63: pop eax
	0xA1, 0xA8, 0x79, 0x40, 0x00, //64: mov eax, FreeLibrary <FIXUP>
	0xFF, 0xD0, //69: call eax
	0x58, //6B: pop eax
	0x5B, //6C: pop ebx
	0x81, 0xC4, 0x00, 0x08, 0x00, 0x00, //6D: add esp, 0x800
	0x53, //73: push ebx
	0xC3, //74: ret

	0x90, 0x90, 0x90, 0x90, //0x75 - 0x7F: padding?
	0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90
};


const int f176A6_SIZE = 0x20;
const char HiddenData[f176A6_SIZE] = {
	0x3A, 0xAE, 0x69, 0x16, 0x64, 0x15, 0x65, 0x27, 0x8E, 0x7C, 0x60, 0x38, 0xB8, 0xE3, 0x5B, 0x49,
	0xE2, 0x4A, 0x57, 0x5A, 0x0C, 0xB2, 0x52, 0x6B, 0x36, 0x19, 0x4E, 0x7C, 0x60, 0x80, 0x49, 0x8D
};

//0x00 - 0x80 = function ported

/*
enum ModifyType {
 XOR = 0xB, ADD = 0xA
};

void ModifyValue(int modifyValue, ModifyType type)
{
  void* eax = 0x435088; //Comes from Intense Checking
  for(int i = 0; i < 4; ++i)
  {
    int value;
    memcpy(&value, eax, 4);
    if(type == ModifyType::ADD)
      value += modifyValue;
    else if(type == ModifyType::XOR)
      value ^= 0x12;
    memcpy(eax, value, 4);
    eax += 4;
  }
}
*/

LPVOID CreateMDJFileMap(int pid)
{
	char name[19];
	memset(name, 0, sizeof(name));
	_snprintf(name, sizeof(name), "MDJ240167_%08X", pid);
	name[18] = 0; //shouldn't be necessary
	DWORD flProtect = PAGE_READWRITE | SEC_COMMIT;
	printf("Creating shared memory with name: %s, flProtect: 0x%X\n", name, flProtect);
	HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, flProtect, 0, FILEMAP_SIZE, name);
	if(hMap == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create shared memory\n");
		return NULL;
	}
	LPVOID mapView = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0);
	if(mapView == NULL)
	{
		printf("Failed top create mapView");
		return NULL;
	}
	return mapView;
}

void InjectDebug(PROCESS_INFORMATION& info)
{
	CONTEXT c;
	ZeroMemory(&c, sizeof(CONTEXT));
	c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_i386;
	GetThreadContext(info.hThread, &c);
	DWORD esp = c.Esp;

	std::string s_dplayerx = "dplayerx";
	std::string s_Ox77F052CC5 = "Ox77F052CC5";
	DWORD dLoadLibraryA = 0x7C801D7B;
	DWORD dFreeLibrary = 0x7C80AC6E;
	DWORD dGetProcAddress = 0x7C80AE30;	
	unsigned char* memory = new unsigned char[0xB5 + 0x15];
	memset(memory, 0, 0xB5 + 0x15);
	memcpy(memory, ModifiedInjectedFunc, MODIFIED_FUNCWITHSTACK_SIZE);

	//TODO: DWORD argAddress = esp - 0x39;
	memcpy(&memory[0x00], &dLoadLibraryA, 4);
	memcpy(&memory[0x04], &dGetProcAddress, 4);
	memcpy(&memory[0x08], &dFreeLibrary, 4);
	//TODO: memcpy(&memory[0x0C], &argAddress, 4);
	memcpy(&memory[0x10], s_Ox77F052CC5.c_str(), s_Ox77F052CC5.size());
	memcpy(&memory[0x24], s_dplayerx.c_str(), s_dplayerx.size());
	
	DWORD dplayerx_stackAddress = esp - 0x99;
	DWORD lla_stackAddress = esp - 0xBD;
	DWORD Ox77_stackAddress = esp - 0xAD;
	DWORD gpa_stackAddress = esp - 0xB9;
	DWORD mv_stackAddress = esp - 0xB1;
	DWORD fl_stackAddress = esp - 0xB5;
	memcpy(&memory[0x3B + 0x15], &dplayerx_stackAddress, 4);
	memcpy(&memory[0x40 + 0x15], &lla_stackAddress, 4);
	memcpy(&memory[0x4C + 0x15], &Ox77_stackAddress, 4);
	memcpy(&memory[0x52 + 0x15], &gpa_stackAddress, 4);
	memcpy(&memory[0x5D + 0x15], &mv_stackAddress, 4);
	memcpy(&memory[0x65 + 0x15], &fl_stackAddress, 4);

	//0095: file at dwEntry + 176A6
	const int f176A6_iSize = f176A6_SIZE / sizeof(int);
	int HiddenDataDecrypted[f176A6_iSize];
	memcpy(HiddenDataDecrypted, HiddenData, f176A6_SIZE);
	const int modifyValue = 0x19;
	for(int i = 0; i < 8; ++i)
		HiddenDataDecrypted[i] ^= modifyValue; 
	memcpy(&memory[0x95 + 0x15], (char*)HiddenDataDecrypted, f176A6_SIZE);

	DWORD nextEip = esp - 0x85;
	DWORD baseAddress = esp - 0xBD; //12FF3F
	DWORD eip = c.Eip;	
	c.Ebx = eip;
	c.Esp = esp - 0x800;
	c.Eip = nextEip;
	c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_i386;
	SetThreadContext(info.hThread, &c);
	SIZE_T bytesWritten;
	WriteProcessMemory(info.hProcess, (LPVOID)baseAddress, memory, 0xB5, &bytesWritten);
	printf("Injected at: 0x%08X, eip = 0x%08X\n", baseAddress, nextEip);
	for(int i = 0; i < (0xB5 + 0x15); ++i)
	{
		if((i % 0x10) == 0)
			printf("%03X: ", i);
		printf("%02X ", memory[i] % 0xFF);
		if(((i + 1) % 0x10) == 0)
			printf("\n");
	}
	printf("\n");
	delete memory;
}

void Inject(PROCESS_INFORMATION& info)
{
	CONTEXT c;
	ZeroMemory(&c, sizeof(CONTEXT));
	c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_i386;
	GetThreadContext(info.hThread, &c);
	DWORD esp = c.Esp;

	std::string s_dplayerx = "dplayerx";
	std::string s_Ox77F052CC5 = "Ox77F052CC5";

	//They literally hardcode these values
	DWORD dLoadLibraryA = 0x7C801D7B;
	DWORD dFreeLibrary = 0x7C80AC6E;
	DWORD dGetProcAddress = 0x7C80AE30;
	
	//Includes stack and code
	//12FF3F = start of data
	//12FF77 = eip

	
	//Memory Layout:
	//0x00 - 0x80 = Injected Function
	//0x80 - 0xB5 = Unknown
	
	unsigned char* memory = new unsigned char[0xB5];
	memset(memory, 0, 0xB5);
	memcpy(memory, InjectedFuncWithStack, INJECTED_FUNCWITHSTACK_SIZE);

	//0000: LoadLibraryA
	//0004: GetProcAddress
	//0008: FreeLibrary
	//000C: Stack Address 12FFC3 (-0x39), 0x38 + 0x0C (12FF3F + 84) ModifyValues*
	//0010: "Ox77F052C" (takes 3 dwords)
	//0024: "dplayerx" (takes 3 dwords)

	//TODO: DWORD argAddress = esp - 0x39;
	memcpy(&memory[0x00], &dLoadLibraryA, 4);
	memcpy(&memory[0x04], &dGetProcAddress, 4);
	memcpy(&memory[0x08], &dFreeLibrary, 4);
	//TODO: memcpy(&memory[0x0C], &argAddress, 4);
	memcpy(&memory[0x10], s_Ox77F052CC5.c_str(), s_Ox77F052CC5.size());
	memcpy(&memory[0x24], s_dplayerx.c_str(), s_dplayerx.size());
	
	//Modifying the code in-line:
	//0038: Code Start
	//003B: Stack Address 12FF63 (-0x99), 0x38 + 0x03 (12FF3F + 24) dplayerx
	//0040: Stack Address 12FF3F (-0xBD), 0x38 + 0x08 (12FF3F + 00) LoadLibraryA
	//004C: Stack Address 12FF4F (-0xAD), 0x38 + 0x14 (12FF3F + 10) Ox77F052C
	//0052: Stack Address 12FF43 (-0xB9), 0x38 + 0x1A (12FF3F + 04) GetProcAddress
	//005D: Stack Address 12FF4B (-0xB1), 0x38 + 0x25 (12FF3F + 10) ModifyValues* - arg to Ox77F func
	//0065: Stack Address 12FF47 (-0xB5), 0x38 + 0x2D (12FF3F + 08) FreeLibrary

	DWORD dplayerx_stackAddress = esp - 0x99;
	DWORD lla_stackAddress = esp - 0xBD;
	DWORD Ox77_stackAddress = esp - 0xAD;
	DWORD gpa_stackAddress = esp - 0xB9;
	DWORD mv_stackAddress = esp - 0xB1;
	DWORD fl_stackAddress = esp - 0xB5;
	memcpy(&memory[0x3B], &dplayerx_stackAddress, 4);
	memcpy(&memory[0x40], &lla_stackAddress, 4);
	memcpy(&memory[0x4C], &Ox77_stackAddress, 4);
	memcpy(&memory[0x52], &gpa_stackAddress, 4);
	memcpy(&memory[0x5D], &mv_stackAddress, 4);
	memcpy(&memory[0x65], &fl_stackAddress, 4);

	
	//Additional Data:
	//0084: ModifyValues[0] 78DE02A2
	//0088: ModifyValues[1] 78DE02A2
	//008C: ModifyValues[2] 78DE02A2
	//0090: ModifyValues[3] 78DE02A2
	//0094: wShowWindowResult = 0x33

	//TODO ---

	//0095: file at dwEntry + 176A6
	const int f176A6_iSize = f176A6_SIZE / sizeof(int);
	int HiddenDataDecrypted[f176A6_iSize];
	memcpy(HiddenDataDecrypted, HiddenData, f176A6_SIZE);
	const int modifyValue = 0x19;
	for(int i = 0; i < 8; ++i)
		HiddenDataDecrypted[i] ^= modifyValue; 
	memcpy(&memory[0x95], (char*)HiddenDataDecrypted, f176A6_SIZE);

	DWORD nextEip = esp - 0x85;
	DWORD baseAddress = esp - 0xBD; //12FF3F
	DWORD eip = c.Eip;	
	c.Ebx = eip;
	c.Esp = esp - 0x800;
	c.Eip = nextEip;
	c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_i386;
	SetThreadContext(info.hThread, &c);
	SIZE_T bytesWritten;
	WriteProcessMemory(info.hProcess, (LPVOID)baseAddress, memory, 0xB5, &bytesWritten);
	printf("Injected at: 0x%08X, eip = 0x%08X\n", baseAddress, nextEip);
	for(int i = 0; i < 0xB5; ++i)
	{
		if((i % 0x10) == 0)
			printf("%03X: ", i);
		printf("%02X ", memory[i] % 0xFF);
		if(((i + 1) % 0x10) == 0)
			printf("\n");
	}
	printf("\n");
	delete memory;
}


int main(int argc, const char** argv)
{
	if(argc < 3)
	{
		printf("Usage: %s <icd file> <exe file>\n", argv[0]);
		return 1;
	}
	std::string commandLine(argv[2]);
	commandLine.append("\\\"d\"");
	STARTUPINFOA startup;
	ZeroMemory(&startup, sizeof(STARTUPINFOA));
	startup.cb = sizeof(STARTUPINFOA);
	startup.lpTitle = "GameBoy";
	startup.dwFlags = STARTF_USESHOWWINDOW;
	startup.wShowWindow = 1;

	printf("lpApplicationName: %s\n", argv[1]);
	printf("lpCommandLine %s\n", commandLine.c_str());
	PROCESS_INFORMATION processInformation;
	DWORD dwCreationFlags = CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	CreateProcessA(argv[1], (LPSTR)commandLine.c_str(), NULL, NULL,
		TRUE, dwCreationFlags, NULL, NULL, &startup, &processInformation);
	printf("Created ICD process with pid: 0x%X\n", processInformation.dwProcessId);
	LPVOID mapView = CreateMDJFileMap(processInformation.dwProcessId);
	if(mapView == NULL)
		return 1;
	memcpy(mapView, FileMapData, FILEMAP_SIZE);
	printf("Press any key to inject...\n");
	_getch();
	InjectDebug(processInformation);
	printf("Press any key to resume thread...\n");
	_getch();
	ResumeThread(processInformation.hThread);
	printf("\n");
	return 0;
}