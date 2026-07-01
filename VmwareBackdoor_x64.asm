; VmwareBackdoor_x64.asm
; MASM module for the VMware I/O backdoor port check on x64 MSVC, which
; cannot express this as inline asm (no inline asm support in x64 builds).
;
; Build: add to your VS project and enable
;   Project Properties > Build Customizations > masm
; or assemble standalone: ml64 /c VmwareBackdoor_x64.asm
;
; Declared in C++ (see Quicksand.h) as:
;   extern "C" unsigned int VmwareBackdoorCheck_Asm();
;
; Returns the EBX value after the backdoor I/O call. The caller compares
; it against the expected magic and wraps the call in __try/__except,
; since this faults with a privileged-instruction exception on bare
; metal. PROC FRAME + .pushreg/.endprolog below are not cosmetic — x64
; SEH is table-based, so the unwinder needs this metadata to walk back
; through this frame to find that __except handler when the fault fires.

.code

VmwareBackdoorCheck_Asm PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    mov eax, 564D5868h   ; 'VMXh' magic
    mov ebx, 0
    mov ecx, 0Ah         ; command 0x0A: get VMware version/type
    mov edx, 5658h       ; 'VX' backdoor port
    in eax, dx
    mov eax, ebx         ; return EBX so the C++ side owns the comparison

    pop rbx
    ret
VmwareBackdoorCheck_Asm ENDP

END
