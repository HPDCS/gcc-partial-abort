//~ #include "libitm_i.h"

//~ /*  Define per le due funzioni */
//~ #define offsetof_ext_jmpbuf_rax		0
//~ #define offsetof_ext_jmpbuf_rdx		8
//~ #define offsetof_ext_jmpbuf_rcx		16
//~ #define offsetof_ext_jmpbuf_rbx		24
//~ #define offsetof_ext_jmpbuf_rsp		32
//~ #define offsetof_ext_jmpbuf_rbp		40
//~ #define offsetof_ext_jmpbuf_rsi		48
//~ #define offsetof_ext_jmpbuf_rdi		56
//~ #define offsetof_ext_jmpbuf_r8		64
//~ #define offsetof_ext_jmpbuf_r9		72
//~ #define offsetof_ext_jmpbuf_r10		80
//~ #define offsetof_ext_jmpbuf_r11		88
//~ #define offsetof_ext_jmpbuf_r12		96
//~ #define offsetof_ext_jmpbuf_r13		104
//~ #define offsetof_ext_jmpbuf_r14		112
//~ #define offsetof_ext_jmpbuf_r15		120
//~ #define offsetof_ext_jmpbuf_rip		128
//~ #define offsetof_ext_jmpbuf_flags	136
//~ #define offsetof_ext_jmpbuf_fpu		144

//~ #define old_flags	0
//~ #define old_r11		8
//~ #define old_rax		16
//~ #define ret_addr	24
//~ #define old_rdi		32

//~ /* Needed to convert the defines into strings that can be concatenated */
//~ #define DCHPC_STRINGIFY(X) #X
//~ #define DCHPC_STR(X) DCHPC_STRINGIFY(X)

//~ /* Qui definiamo le funzioni che andremo a usare */
//~ /* Per mantenere il codice pulito, si usa la concatenazione delle stringhe e dei valori definiti con define */

//~ // Vedere se funziona
//~ static long long _ext_setjmp(ext_jmpbuf *jb) {
	//~ asm volatile (\
		//~ "pushq %rax													\n"\
		//~ "pushq %r11													\n"\
																	   //~ \
		//~ "lahf														\n"\
		//~ "seto %al													\n"\
		//~ "pushq %rax													\n"\
																	   //~ \
		//~ "movq %rdi, %rax											\n"\
		//~ "movq " DCHPC_STR(old_rax) "(%rsp), %r11					\n"\
																	   //~ \
		//~ "movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_rax) "(%rax)	\n"\
		//~ "movq %rdx, " DCHPC_STR(offsetof_ext_jmpbuf_rdx) "(%rax)	\n"\
		//~ "movq %rcx, " DCHPC_STR(offsetof_ext_jmpbuf_rcx) "(%rax)	\n"\
		//~ "movq %rbx, " DCHPC_STR(offsetof_ext_jmpbuf_rbx) "(%rax)	\n"\
		//~ "movq %rsp, " DCHPC_STR(offsetof_ext_jmpbuf_rsp) "(%rax)	\n"\
		//~ "addq $16,  " DCHPC_STR(offsetof_ext_jmpbuf_rsp) "(%rax)	\n"\
		//~ "movq %rbp, " DCHPC_STR(offsetof_ext_jmpbuf_rbp) "(%rax)	\n"\
		//~ "movq %rsi, " DCHPC_STR(offsetof_ext_jmpbuf_rsi) "(%rax)	\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(old_rdi) "(%rsp), %r11					\n"\
		//~ "movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_rdi) "(%rax)	\n"\
		//~ "movq %r8, " DCHPC_STR(offsetof_ext_jmpbuf_r8) "(%rax)		\n"\
		//~ "movq %r9, " DCHPC_STR(offsetof_ext_jmpbuf_r9) "(%rax)		\n"\
		//~ "movq %r10, " DCHPC_STR(offsetof_ext_jmpbuf_r10) "(%rax)	\n"\
		//~ "movq " DCHPC_STR(old_r11) "(%rsp), %r11					\n"\
		//~ "movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_r11) "(%rax)	\n"\
		//~ "movq %r12, " DCHPC_STR(offsetof_ext_jmpbuf_r12) "(%rax)	\n"\
		//~ "movq %r13, " DCHPC_STR(offsetof_ext_jmpbuf_r13) "(%rax)	\n"\
		//~ "movq %r14, " DCHPC_STR(offsetof_ext_jmpbuf_r14) "(%rax)	\n"\
		//~ "movq %r15, " DCHPC_STR(offsetof_ext_jmpbuf_r15) "(%rax)	\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(old_flags) "(%rsp), %rdx					\n"\
		//~ "movq %rdx, " DCHPC_STR(offsetof_ext_jmpbuf_flags) "(%rax)	\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(ret_addr) "(%rsp), %r11					\n"\
		//~ "movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_rip) "(%rax)	\n"\
																	   //~ \
		//~ "fxsave " DCHPC_STR(offsetof_ext_jmpbuf_fpu) "(%rax)		\n"\
																	   //~ \
		//~ "addq $24, %rsp												\n"\
		//~ "xorq %rax, %rax											\n"\
		//~ "ret														"\
	//~ );
	//~ /* Any code here is unreachable */
	//~ return 0;
//~ }

//~ // Vedere se funziona
//~ __attribute__ ((__noreturn__))
//~ static void _ext_longjmp(ext_jmpbuf *jb, long long val){
	//~ asm volatile(\
		//~ "movq %rdi, %rax											\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rip ) "(%rax), %r10	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rsp ) "(%rax), %r11	\n"\
		//~ "movq %r10, 8(%r11)											\n"\
																	   //~ \
		//~ "movq %rsi, (%r11)											\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rdx) "(%rax), %rdx	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rcx) "(%rax), %rcx	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rbx) "(%rax), %rbx	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rsp) "(%rax), %rsp	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rbp) "(%rax), %rbp	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rsi) "(%rax), %rsi	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r8) "(%rax), %r8		\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r9) "(%rax), %r9		\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r10) "(%rax), %r10	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r11) "(%rax), %r11	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r12) "(%rax), %r12	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r13) "(%rax), %r13	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r14) "(%rax), %r14	\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_flags) "(%rax), %rax	\n"\
		//~ "addb $0x7f, %al											\n"\
		//~ "sahf														\n"\
																	   //~ \
		//~ "movq %rdi, %rax											\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rdi) "(%rax), %rdi	\n"\
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_r15) "(%rax), %r15	\n"\
																	   //~ \
		//~ "fxrstor " DCHPC_STR(offsetof_ext_jmpbuf_fpu) "(%rax)		\n"\
																	   //~ \
		//~ "movq " DCHPC_STR(offsetof_ext_jmpbuf_rsp) "(%rax), %rsp	\n"\
																	   //~ \
		//~ "popq %rax													\n"\
		//~ "ret														"\
	//~ );
	//~ /* Unreachable. Added to satisfy the __noreturn__ attribute */
	//~ while(true){}
//~ }


//~ /* undefine */
//~ #undef old_flags
//~ #undef old_r11
//~ #undef old_rax
//~ #undef ret_addr
//~ #undef old_rdi

//~ #undef offsetof_ext_jmpbuf_rax	
//~ #undef offsetof_ext_jmpbuf_rdx	
//~ #undef offsetof_ext_jmpbuf_rcx	
//~ #undef offsetof_ext_jmpbuf_rbx	
//~ #undef offsetof_ext_jmpbuf_rsp	
//~ #undef offsetof_ext_jmpbuf_rbp	
//~ #undef offsetof_ext_jmpbuf_rsi	
//~ #undef offsetof_ext_jmpbuf_rdi	
//~ #undef offsetof_ext_jmpbuf_r8	
//~ #undef offsetof_ext_jmpbuf_r9	
//~ #undef offsetof_ext_jmpbuf_r10	
//~ #undef offsetof_ext_jmpbuf_r11	
//~ #undef offsetof_ext_jmpbuf_r12	
//~ #undef offsetof_ext_jmpbuf_r13	
//~ #undef offsetof_ext_jmpbuf_r14	
//~ #undef offsetof_ext_jmpbuf_r15	
//~ #undef offsetof_ext_jmpbuf_rip	
//~ #undef offsetof_ext_jmpbuf_flags
//~ #undef offsetof_ext_jmpbuf_fpu	

//~ #undef DCHPC_STR
//~ #undef DCHPC_STRINGIFY
