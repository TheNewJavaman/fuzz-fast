# fuzz-fast

GPU-accelerated fuzzing by emulating x86 on CUDA.

## Sample

- C
    ```c
    #include <stddef.h>
    #include <stdint.h>

    uint16_t vulnerable(uint8_t *data, size_t size) {
        // Issue 1: Buffer overflow
        uint8_t buffer[10];
        for (size_t i = 0; i < size; i++) {
            buffer[i] = data[i];
        }

        // Issue 2: Uninitialized memory
        uint16_t sum = 0;
        for (size_t i = 0; i < 5; i++) {
            sum += buffer[i];
        }
        return sum;
    }
    ```
- x86
    ```
    0x0: push rbp
    0x1: mov rbp, rsp
    0x4: mov qword ptr [rbp - 8], rdi
    0x8: mov qword ptr [rbp - 0x10], rsi
    0xc: mov qword ptr [rbp - 0x28], 0
    0x14: mov rax, qword ptr [rbp - 0x28]
    0x18: cmp rax, qword ptr [rbp - 0x10]
    0x1c: jae 0x3f
    0x1e: mov rax, qword ptr [rbp - 8]
    0x22: mov rcx, qword ptr [rbp - 0x28]
    0x26: mov cl, byte ptr [rax + rcx]
    0x29: mov rax, qword ptr [rbp - 0x28]
    0x2d: mov byte ptr [rbp + rax - 0x1a], cl
    0x31: mov rax, qword ptr [rbp - 0x28]
    0x35: add rax, 1
    0x39: mov qword ptr [rbp - 0x28], rax
    0x3d: jmp 0x14
    0x3f: mov word ptr [rbp - 0x2a], 0
    0x45: mov qword ptr [rbp - 0x38], 0
    0x4d: cmp qword ptr [rbp - 0x38], 5
    0x52: jae 0x75
    0x54: mov rax, qword ptr [rbp - 0x38]
    0x58: movzx ecx, byte ptr [rbp + rax - 0x1a]
    0x5d: movzx eax, word ptr [rbp - 0x2a]
    0x61: add eax, ecx
    0x63: mov word ptr [rbp - 0x2a], ax
    0x67: mov rax, qword ptr [rbp - 0x38]
    0x6b: add rax, 1
    0x6f: mov qword ptr [rbp - 0x38], rax
    0x73: jmp 0x4d
    0x75: movzx eax, word ptr [rbp - 0x2a]
    0x79: pop rbp
    0x7a: ret
    ```
- PTX
    ```
    L_0:    sub.u64 rsp, rsp, 8;
            st.local.u64 [stack + rsp], rbp;
    L_1:    mov.u64 rbp, rsp;
    L_4:    st.local.u64 [stack + rbp + -8], rdi;
    L_8:    st.local.u64 [stack + rbp + -16], rsi;
    L_C:    st.local.s64 [stack + rbp + -40], 0;
    L_14:   ld.local.u64 rax, [stack + rbp + -40];
    L_18:   setp.lt.s64 cf, rax, [stack + rbp + -16];
            setp.eq.s64 zf, rax, [stack + rbp + -16];
    L_1C:   @!cf bra L_3F;
    L_1E:   ld.local.u64 rax, [stack + rbp + -8];
    L_22:   ld.local.u64 rcx, [stack + rbp + -40];
    L_26:   ld.local.u8 cl, [stack + rax + 0];
    L_29:   ld.local.u64 rax, [stack + rbp + -40];
    L_2D:   st.local.u8 [stack + rbp + -26], cl;
    L_31:   ld.local.u64 rax, [stack + rbp + -40];
    L_35:   add.s64 rax, rax, 1;
    L_39:   st.local.u64 [stack + rbp + -40], rax;
    L_3D:   bra.uni L_14;
    L_3F:   st.local.s64 [stack + rbp + -42], 0;
    L_45:   st.local.s64 [stack + rbp + -56], 0;
    L_4D:   setp.lt.s64 cf, [stack + rbp + -56], 5;
            setp.eq.s64 zf, [stack + rbp + -56], 5;
    L_52:   @!cf bra L_75;
    L_54:   ld.local.u64 rax, [stack + rbp + -56];
    L_58:   ld.local.u32 ecx, [stack + rbp + -26];
            and.b32 ecx, ecx, 0xFF;
    L_5D:   ld.local.u32 eax, [stack + rbp + -42];
            and.b32 eax, eax, 0xFFFF;
    L_61:   add.u32 eax, eax, ecx;
    L_63:   st.local.u16 [stack + rbp + -42], ax;
    L_67:   ld.local.u64 rax, [stack + rbp + -56];
    L_6B:   add.s64 rax, rax, 1;
    L_6F:   st.local.u64 [stack + rbp + -56], rax;
    L_73:   bra.uni L_4D;
    L_75:   ld.local.u32 eax, [stack + rbp + -42];
            and.b32 eax, eax, 0xFFFF;
    L_79:   ld.local.u64 rbp, [stack + rsp];
            add.u64 rsp, rsp, 8;
    ```

## Todo

- Misc. registers (e.g. `EIP`)
- High-byte registers (e.g. `AH`)
- `cmp` flags (`CF`, `ZF` done)
