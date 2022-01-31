/*!
* \file main.cc
* \brief Main file of PlutoGNSS device test program.
* \author Javier Arribas, 2022. jarribas(at)cttc.es
*
* -------------------------------------------------------------------------
*
* Copyright (C) 2021 (see AUTHORS file for a list of contributors)
*
* This file is part of PLUTOGNSS.
*
*/

#ifndef PLUTOGNSSTEST_VERSION
#define PLUTOGNSSTEST_VERSION "0.0.1"
#endif

#include "ip_regs_pps_samplestamp.h"
#include <boost/exception/diagnostic_information.hpp>  // for diagnostic_information
#include <boost/exception/exception.hpp>               // for exception
#include <boost/thread/exceptions.hpp>                 // for thread_resource_error
#include <exception>                                   // for exception
#include <fcntl.h>                                     // for open, O_RDWR, O_SYNC
#include <iostream>
#include <string>
#include <sys/mman.h>  // for mmap

extern "C"
{
#include "uio_helper.h"
}


std::string FindDeviceByCoreName(std::string IP_name)
{
    std::string device_name = "";

    struct uio_info_t *info_list, *p;

    info_list = uio_find_devices(-1);
    if (!info_list)
        {
            std::cout << "No UIO devices found.\n";
            return device_name;
        }

    p = info_list;

    while (p)
        {
            uio_get_all_info(p);
            uio_get_device_attributes(p);
            std::string uio_name(p->name);
            std::cerr << "found: device uio" << std::to_string(p->uio_num) << " with name: " << uio_name << "\n";
            if (uio_name == IP_name)
                {
                    std::cerr << "match: " << uio_name << "\n";
                    device_name = "/dev/uio" + std::to_string(p->uio_num);
                    break;
                }
            p = p->next;
        }

    uio_free_info(info_list);

    if (device_name == "")
        {
            std::cerr << "The device " << IP_name.c_str() << " is not present in UIO driver" << std::endl;
            return device_name;
        }
    else
        {
            std::cerr << "Found device " << device_name.c_str() << " asociated with " << IP_name.c_str() << std::endl;
        }
    return device_name;
}


int main(int argc, char **argv)
{
    const std::string intro_help(
        std::string("\nPLUTOGNSSTEST is a dummy test program for testing PlutoGNSS package build configuration.\n") +
        "Copyright (C) 2022 (see AUTHORS file for a list of contributors)\n" +
        "This program comes with ABSOLUTELY NO WARRANTY;\n" +
        "See COPYING file to see a copy of the General Public License\n \n");

    const std::string version(PLUTOGNSSTEST_VERSION);

    std::cout << "Initializing PLUTOGNSSTEST v" << version << " ... Please wait." << std::endl;

    volatile unsigned *pps_samplestamp_map_base;
    int pps_samplestamp_device_descriptor;


    std::string device_name = FindDeviceByCoreName("pps_samplestamp");
    if (device_name == "")
        {
            std::cerr << "PPS Samplestamp IP core not found!\n";
            return false;
        }
    if ((pps_samplestamp_device_descriptor = open(device_name.c_str(), O_RDWR | O_SYNC)) == -1)
        {
            std::cerr << "Cannot open device UIO " << device_name.c_str() << "\n";
            return false;
        }
    // constants
    const size_t PAGE_SIZE = 0x10000;
    pps_samplestamp_map_base = reinterpret_cast<volatile unsigned *>(
        mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
            pps_samplestamp_device_descriptor, 0));

    if (pps_samplestamp_map_base == reinterpret_cast<void *>(-1))
        {
            std::cerr << "Cannot map the FPGA IP module PPS Samplestamp into memory (UIO dev: " << device_name.c_str() << ")\n";
            return false;
        }
    else
        {
            std::cerr << "FPGA IP module PPS Samplestamp memory successfully mapped (UIO dev: " << device_name.c_str() << ")\n";
        }

    // sanity check : check version register

    uint32_t readval = pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_READ_HW_VERSION_REG];
    uint32_t ip_hw_type = (readval & 0xFF00) >> 8;
    uint32_t ip_hw_version = (readval & 0x00FF) >> 8;

    std::cerr << "Detected IP PPS Samplestamp with HW Type " << ip_hw_type
              << " rev. " << ip_hw_version << "\n";
    if (ip_hw_type != PPS_SAMPLESTAMP_IP_HW_TYPE)
        {
            std::cerr << "The device " << device_name.c_str() << " does not match the expected HW type" << std::endl;
            return false;
        }


    std::cout << "PLUTOGNSSTEST program ended." << std::endl;
    int return_code = 0;
    return return_code;
}
