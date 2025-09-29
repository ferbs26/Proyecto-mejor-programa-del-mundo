; Demonstrates CALL/RET and LOAD/STORE memory usage
; Computes square(7) using memory cell 0
PUSH 7
CALL square
PRINT       ; expect 49
HALT

square:
STORE 0     ; pop input into mem[0]
LOAD 0
LOAD 0
MUL
RET
