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

#include <boost/exception/diagnostic_information.hpp>  // for diagnostic_information
#include <boost/exception/exception.hpp>               // for exception
#include <boost/thread/exceptions.hpp>                 // for thread_resource_error
#include <exception>  // for exception
#include <iostream>


int main(int argc, char** argv)
{
    const std::string intro_help(
        std::string("\nPLUTOGNSSTEST is a dummy test program for testing PlutoGNSS package build configuration.\n") +
        "Copyright (C) 2022 (see AUTHORS file for a list of contributors)\n" +
        "This program comes with ABSOLUTELY NO WARRANTY;\n" +
        "See COPYING file to see a copy of the General Public License\n \n");

    const std::string version(PLUTOGNSSTEST_VERSION);

    std::cout << "Initializing PLUTOGNSSTEST v" << version << " ... Please wait." << std::endl;

    std::cout << "PLUTOGNSSTEST program ended." << std::endl;
    int return_code = 0;
    return return_code;
}
