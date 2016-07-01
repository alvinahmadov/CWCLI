#ifndef _ERR_CONV_H_
#define _ERR_CONV_H_

CWERROR pterr_to_cwerr(const CW_PE_CODE err);

CW_PE_CODE cwerr_to_pterr(const CWERROR err);

#endif
