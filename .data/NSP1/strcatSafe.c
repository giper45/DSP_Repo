#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char** argv){

	char buff[50];
	buff[0] = 's';
	buff[1] = 't';
	buff[2] = 'r';
	buff[3] = ':';
	strncat(buff,argv[1],46);
	printf("%s \n",buff);
	return 1;

}
