#ifndef IP_REGS_PPS_SAMPLESTAMP_H
#define IP_REGS_PPS_SAMPLESTAMP_H
#include <cstdint>
// Expected HW IP_TYPE_ID
//-- 32 bits registers
//---Read Register @0: bits 15 to 8 = IP_TYPE_ID, bits 7 to 0 = IP_HW_VERSION
//---Read Register @1: last PPS rising edge 64 bits sample counter (32 bits lower nibble)
//---Read Register @2: last PPS rising edge 64 bits sample counter (32 bits upper nibble)
//---Read Register @3: overflow flag
//---Write Register @0: clear overflow flag
//---Write Register @1: clear interrupt flag

const uint32_t PPS_SAMPLESTAMP_IP_HW_TYPE = 110;
//WRITE REGS
const int32_t PPS_SAMPLESTAMP_IP_WRITE_CLEAR_OVERFLOW_FLAG = 0;
const int32_t PPS_SAMPLESTAMP_IP_WRITE_CLEAR_INTERRUPT_FLAG = 1;

//READ REGS
//read IP HW TYPE and VERSION: lower byte is HW_VERSION and next byte is IP_TYPE
const int32_t PPS_SAMPLESTAMP_IP_READ_HW_VERSION_REG = 0;
//read sample counter value (64 BITS UNSIGNED) 32 bits low nibble
const int32_t PPS_SAMPLESTAMP_IP_READ_SAMPLE_COUNT_L_REG = 1;
//read sample counter value (64 BITS UNSIGNED) 32 bits high nibble
const int32_t PPS_SAMPLESTAMP_IP_READ_SAMPLE_COUNT_H_REG = 2;
//read overflow flag
const int32_t PPS_SAMPLESTAMP_IP_READ_OVERFLOW_REG = 3;

#endif
