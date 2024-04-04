## Todo

- Reuse 64 bit registers for 32 bit operations:
    ```ptx
    .reg .u64 u64_register;   // Define a 64-bit register
    .reg .u32 u32_register;   // Define a 32-bit register
    
    // Some code to populate u64_register...
    
    // Extract the lower 32 bits into u32_register
    and.u32 u32_register, u64_register, 0xFFFFFFFF;
    ```
- All flags for `cmp`
