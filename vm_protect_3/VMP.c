
// Compiled with mingw "gcc.exe -masm=intel -o VMP.exe "./VMP.c"


void virtualized(){

    int V;
    char abc[10];

    scanf("%10s", abc);

    __asm__ (
        "mov ebx, 0x11111111;"
        "mov ebx, 0x22222222;"
        "mov ebx, 0x33333333;"
        "mov ebx, 0x44444444;"
        "mov ebx, 0x55555555;"
        "mov ebx, 0x66666666;"
        "mov ebx, 0x77777777;"
        "mov ebx, 0x88888888;"
        "mov ebx, 0x99999999;"
        "mov ebx, 0xaaaaaaaa;"
        "mov ebx, 0xbbbbbbbb;"
        "mov ebx, 0xcccccccc;"
        "mov ebx, 0xdddddddd;"
        "mov ebx, 0xeeeeeeee;"
        "mov ebx, 0xffffffff;"

        "add ebx, 0x1;"
        "add ebx, 0x1;"
        "add ebx, 0x1;"
        "add ebx, 0x1;"
        "add ebx, 0x1;"
        "add ebx, 0x1;"
        "add ebx, 0x1;"
        "sub ebx, 0x1;"
        "sub ebx, 0x1;"
        "sub ebx, 0x1;"
        "sub ebx, 0x1;"
        "sub ebx, 0x1;"
        "sub ebx, 0x1;"
        "sub ebx, 0x1;"

        "mov eax, ebx;"

        : "=r" (V)

    );

    printf("Val: %x\n", V);

}

void main(){

    __asm__(".intel_syntax;");

    int x;
    char abc[10];
    printf("GO!\n");

    for (x=0;x<1000; x++){
        virtualized();
    }

}