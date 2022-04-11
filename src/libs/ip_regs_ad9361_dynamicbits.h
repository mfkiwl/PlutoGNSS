#ifndef IP_REGS_AD9361_DYNAMICBITS
#define IP_REGS_AD9361_DYNAMICBITS
#include <cstdint>
// Expected HW IP_TYPE_ID
//-- 32 bits registers
//-- 32 bits registers
//---Read Register @0: bits 15 to 8 = IP_TYPE_ID, bits 7 to 0 = IP_HW_VERSION
//---Read Register @1: input power estimation (32 bits unsigned)
//---Write Register @0: shift left the desired number of bits for maping SAMPLE_IN to SAMPLE_OUT
//---Write Register @1: set the sample SAMPLE_OUT size: 2, 4, 8, 16
//---Write Register @2: enable the sample pattern test output: 1- enable 0-disable

const uint32_t AD9361_DYNAMICBITS_IP_HW_TYPE = 102;
const uint32_t AD9361_DYNAMICBITS_IP_HW_VERSION = 10;
//WRITE REGS
const int32_t AD9361_DYNAMICBITS_IP_WRITE_BITS_SHIFT_LEFT = 0;
const int32_t AD9361_DYNAMICBITS_IP_WRITE_SAMPLE_OUT_SIZE = 1;
const int32_t AD9361_DYNAMICBITS_IP_WRITE_ENABLE_PATTERN = 2;

//READ REGS
//read IP HW TYPE and VERSION: lower byte is HW_VERSION and next byte is IP_TYPE
const int32_t AD9361_DYNAMICBITS_IP_READ_HW_VERSION_REG = 0;
//read sample counter value (64 BITS UNSIGNED) 32 bits low nibble
const int32_t AD9361_DYNAMICBITS_IP_READ_INPUT_POWER = 1;


#endif
