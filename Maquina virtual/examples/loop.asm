; Example: countdown from 5 to 1, printing each number
PUSH 5
loop:
DUP
PRINT
PUSH 1
SUB
DUP
JNZ loop
POP
HALT
