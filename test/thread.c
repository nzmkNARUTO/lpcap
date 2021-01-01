#include <stdio.h>
#include <string.h>
FILE *f;
int c;
void main(int argc,char **argv) {
    if (argc==3) {
        if (strcmp(argv[1],"-a")) goto USAGE;
        f=fopen(argv[2],"a");
        if (NULL==f) goto FNULL;
        goto FOK;
    } else if (argc==2) {
        if (0==strcmp(argv[1],"/?")) {
        USAGE:
            fprintf(stderr,"Usage: program | tee [-a] file\n");
            return;
        }
        f=fopen(argv[1],"w");
        if (NULL==f) goto FNULL;
    FOK:
        while (1) {
            c=getchar();
            if (EOF==c) break;
            if (EOF==fputc(c,f)) {
                putchar(c);
                break;
            } else {
                if (EOF==putchar(c)) break;
            }
        }
        fclose(f);
    } else {
    FNULL:
        while (1) {
            c=getchar();
            if (EOF==c) break;
            if (EOF==putchar(c)) break;
        }
    }
}