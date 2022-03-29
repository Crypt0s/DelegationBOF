DelegationBOF:
	x86_64-w64-mingw32-gcc -c DelegationBOF.c -o delegationx64.o 
	x86_64-w64-mingw32-strip -N DelegationBOF.c delegationx64.o 
