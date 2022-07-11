#include <Windows.h>
#include <stdio.h>

static unsigned char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int base58_encode(const char* input,const unsigned int inLen,unsigned char *output,unsigned int outLen)
{
	int i,j,tmp;
	memset(output,0,outLen);
	for(i=0;i<inLen;i++)
	{
		unsigned int c = input[i] & (0xff) ;
		for(j=outLen-1;j>=0;j--)
		{
			tmp = output[j] * 256 + c;
			c = tmp/58;
			output[j] = tmp%58;
		}
	}
	for(j=0; j<outLen; ++j)
	{
		output[j] = alphabet[output[j]];
	}
	return 0;
}