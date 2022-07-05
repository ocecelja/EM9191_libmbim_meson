#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include "switype_256bit.h"

void swi_uint256_set_bit(swi_uint256_t *pMask,uint8_t bit)
{
    if(pMask)
    {
        pMask->word[SWI_UINT256_WORD_OFFSET(bit)] |= (1 << SWI_UINT256_BIT_OFFSET(bit));
    }
}

void swi_uint256_clear_bit(swi_uint256_t *pMask,uint8_t bit)
{
    if(pMask)
    {
        pMask->word[SWI_UINT256_WORD_OFFSET(bit)] &= ~(1 << SWI_UINT256_BIT_OFFSET(bit));
    }
}

uint8_t swi_uint256_get_bit(swi_uint256_t Mask, uint8_t bit)
{
    uint16_t value = Mask.word[SWI_UINT256_WORD_OFFSET(bit)] & (1 << SWI_UINT256_BIT_OFFSET(bit));
    return (value != 0);
}

void swi_uint256_init(swi_uint256_t *pMask)
{
    if (pMask)
        memset (pMask,0,sizeof(swi_uint256_t));
}

void swi_uint256_print_mask(swi_uint256_t mask)
{
    uint8_t i =0;
    char temp[4];
    char buff[SWI_UINT256_WORD_COUNT*SWI_UINT256_BITS_PER_WORD+17]={0};
    // Just to print from the right
    for(i=(SWI_UINT256_WORD_COUNT*SWI_UINT256_BITS_PER_WORD)-1;;i--)
    {
        sprintf(temp,"%d", swi_uint256_get_bit(mask,i));
        strcat(buff,temp);
        if (!(i%SWI_UINT256_BITS_PER_WORD))
            strcat(buff," ");
        if (!i)
            break;
    }
    syslog ( LOG_DEBUG, "%s\n", &buff[0]);
}

bool swi_uint256_is_empty(swi_uint256_t *pMask)
{
	swi_uint256_t empty_mask;

	if (!pMask)
		return true;

	swi_uint256_init(&empty_mask);
	return memcmp(pMask, &empty_mask, sizeof(swi_uint256_t)) == 0;
}
