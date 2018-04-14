#include "LDSSecurityObject.h"

int main(void)
{
	LDSSecurityObject_t *lds;
	lds = (LDSSecurityObject_t*)calloc(1, sizeof *lds);
	if(!lds) exit(1);

	FILE *f=fopen("./lds.bin","rb");
	if(!f) exit(1);
	unsigned char buffer[10000];
	int bufflen;
	bufflen=fread(buffer,1,10000,f);
	fclose(f);

	asn_dec_rval_t 	rval = ber_decode(0,&asn_DEF_LDSSecurityObject,(void**)&lds,buffer,bufflen);
	if(rval.code != RC_OK) exit(1);

	printf("LDS version: %i\n\n",lds->version);
	int i;
	for(i=0;i<lds->dataGroupHashValues.list.count;i++)
	{
			DataGroupHash_t *dgh=lds->dataGroupHashValues.list.array[i];
			printf("Hash of DataGroup %i: \n",dgh->dataGroupNumber);
			int j;
			for(j=0;j<dgh->dataGroupHashValue.size;j++)
				printf("%02X",dgh->dataGroupHashValue.buf[j]);
			printf("\n\n");
	}
	return 0;
}
