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

#ifndef PLUTOGNSSSTSERVER_VERSION
#define PLUTOGNSSSTSERVER_VERSION "0.0.2"
#endif

#include "ip_regs_ad9361_dynamicbits.h"
#include "ip_regs_pps_samplestamp.h"
#include <boost/exception/diagnostic_information.hpp>  // for diagnostic_information
#include <boost/exception/exception.hpp>               // for exception
#include <boost/thread/exceptions.hpp>                 // for thread_resource_error
#include <cstring>                                     // sizeof()
#include <exception>                                   // for exception
#include <fcntl.h>                                     // for open, O_RDWR, O_SYNC
#include <iostream>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/mman.h>  // for mmap
#include <vector>
// headers for socket(), getaddrinfo() and friends
#include "concurrent_queue.h"
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>  // close()


extern "C"
{
#include "uio_helper.h"
}

static volatile bool server_active;
int socket_desc;

volatile unsigned *pps_samplestamp_map_base = NULL;
int pps_samplestamp_device_descriptor;

std::vector<volatile unsigned *> dynamicbits_map_bases;
std::vector<int> dynamicbits_device_descriptors;

//linux daemon stuff
static int pid_fd = -1;
static char *app_name = NULL;
static char *pid_file_name = NULL;

struct pps_info
{
    uint64_t samplestamp;
    uint32_t overflow;
};

std::shared_ptr<Concurrent_Queue<pps_info>> pps_info_queue;


/**
 * \brief Callback function for handling signals.
 * \param	sig	identifier of signal
 */
void handle_signal(int sig)
{
    if (sig == SIGINT)
        {
            std::cout << "Stopping Pluto stserver ...\n";

            server_active = false;
            std::cout << "Sent notification to stop all threads\n";
            pps_info tmp;
            tmp.overflow = 0;
            tmp.samplestamp = 0;
            pps_info_queue->push(tmp);

            // where socketfd is the socket you want to make non-blocking
            int status = fcntl(socket_desc, F_SETFL, fcntl(socket_desc, F_GETFL, 0) | O_NONBLOCK);

            if (status == -1)
                {
                    perror("calling fcntl");
                    // handle the error.  By the way, I've never seen fcntl fail in this way
                }

            /* Unlock and close lockfile */
            if (pid_fd != -1)
                {
                    lockf(pid_fd, F_ULOCK, 0);
                    close(pid_fd);
                }
            /* Try to delete lockfile */
            if (pid_file_name != NULL)
                {
                    unlink(pid_file_name);
                }
            /* Reset signal handling to default behavior */
            signal(SIGINT, SIG_DFL);
        }
    else if (sig == SIGHUP)
        {
            std::cout << "Debug: reloading daemon config file ...\n";
            //todo
        }
    else if (sig == SIGCHLD)
        {
            std::cout << "Debug: received SIGCHLD signal\n";
        }
}

std::vector<std::string> FindDeviceByCoreName(std::string IP_name)
{
    std::vector<std::string> device_names;

    struct uio_info_t *info_list, *p;

    info_list = uio_find_devices(-1);
    if (!info_list)
        {
            std::cout << "No UIO devices found.\n";
            return device_names;
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
                    device_names.push_back("/dev/uio" + std::to_string(p->uio_num));
                }
            p = p->next;
        }

    uio_free_info(info_list);

    if (device_names.empty() == true)
        {
            std::cerr << "The device " << IP_name.c_str() << " is not present in UIO driver" << std::endl;
            return device_names;
        }
    else
        {
            for (auto it = std::begin(device_names); it != std::end(device_names); ++it)
                {
                    std::cerr << "Found device " << it->c_str() << " associated with " << IP_name.c_str() << std::endl;
                }
        }
    return device_names;
}

void tcp_rx_cmd(int FD)
{
    //create a message buffer
    char buf[500];
    std::string new_pps_line;
    while (server_active)
        {
            int numBytesRead = recv(FD, buf, sizeof(buf), 0);
            if (numBytesRead > 0)
                {
                    for (int i = 0; i < numBytesRead; i++)
                        {
                            char c = buf[i];
                            if (c == '\n')
                                {
                                    if (new_pps_line.length() > 0)
                                        {
                                            //sample size (ss)
                                            std::size_t found = new_pps_line.find("ssize=");
                                            if (found != std::string::npos)
                                                {
                                                    int sample_size = std::stoi(new_pps_line.substr(found + 6).c_str(), NULL, 0);
                                                    if (sample_size <= 16 and sample_size > 0)
                                                        {
                                                            //send command to FPGA IP
                                                            std::cout << "Send command to FPGA: " << new_pps_line << "\n";
                                                            for (auto it = std::begin(dynamicbits_map_bases); it != std::end(dynamicbits_map_bases); ++it)
                                                                {
                                                                    (*it)[AD9361_DYNAMICBITS_IP_WRITE_SAMPLE_OUT_SIZE] = sample_size;
                                                                }
                                                        }
                                                    new_pps_line = "";
                                                }
                                            //bits selector bit shift left command (bs)
                                            found = new_pps_line.find("bshift=");
                                            if (found != std::string::npos)
                                                {
                                                    int bit_shift = std::stoi(new_pps_line.substr(found + 7).c_str(), NULL, 0);
                                                    if (bit_shift <= 16 and bit_shift >= 0)
                                                        {
                                                            //send command to FPGA IP
                                                            std::cout << "Send command to FPGA: " << new_pps_line << "\n";
                                                            for (auto it = std::begin(dynamicbits_map_bases); it != std::end(dynamicbits_map_bases); ++it)
                                                                {
                                                                    (*it)[AD9361_DYNAMICBITS_IP_WRITE_BITS_SHIFT_LEFT] = bit_shift;
                                                                }
                                                        }
                                                }
                                            //enable (1) or disable (0) sample pattern counter
                                            found = new_pps_line.find("spattern=");
                                            if (found != std::string::npos)
                                                {
                                                    int enable_pattern = std::stoi(new_pps_line.substr(found + 9).c_str(), NULL, 0);
                                                    if (enable_pattern <= 1 and enable_pattern >= 0)
                                                        {
                                                            //send command to FPGA IP
                                                            std::cout << "Send command to FPGA: " << new_pps_line << "\n";
                                                            for (auto it = std::begin(dynamicbits_map_bases); it != std::end(dynamicbits_map_bases); ++it)
                                                                {
                                                                    (*it)[AD9361_DYNAMICBITS_IP_WRITE_ENABLE_PATTERN] = enable_pattern;
                                                                }
                                                        }
                                                    new_pps_line = "";
                                                }
                                        }
                                    else
                                        {
                                            std::cout << "tcp_rx_cmd debug: protocol error!\n";
                                        }
                                    new_pps_line = "";
                                }

                            else
                                new_pps_line += c;
                        }
                }
            else
                {
                    std::cout << "tcp_rx_cmd: Socket disconnected!\n!";
                    break;
                }
        }
    pps_info tmp;
    tmp.overflow = 0;
    tmp.samplestamp = 0;
    pps_info_queue->push(tmp);
    close(FD);
    std::cout << "tcp_rx_cmd end!\n!";

    return;
}


int tcp_server_single(int port)
{
    std::string portNum = std::to_string(port);
    const unsigned int backLog = 1;  // number of connections allowed on the incoming queue

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); /* WILD CARD FOR IP ADDRESS */
    servaddr.sin_port = htons(port);              /* port number */


    socket_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_desc < 0)
        {
            std::cout << "Fail to create socket..." << std::endl;
            return -1;
        }

    if (bind(socket_desc, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        {
            std::cout << "Fail to bind socket..." << std::endl;
            return -2;
        }

    // finally start listening for connections on our socket
    int listenR = listen(socket_desc, backLog);
    if (listenR == -1)
        {
            std::cerr << "Error while Listening on socket\n";

            // if some error occurs, make sure to close socket and free resources
            close(socket_desc);
            return -6;
        }


    // structure large enough to hold client's address
    sockaddr_storage client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    pps_info new_pps;
    // a fresh infinite loop to communicate with incoming connections
    // this will take client connections one at a time
    // in further examples, we're going to use fork() call for each client connection
    std::thread rx_cmd_thread;
    while (server_active)
        {
            // accept call will give us a new socket descriptor
            std::cout << "Accepting new client...\n";
            int newFD = accept(socket_desc, (sockaddr *)&client_addr, &client_addr_size);
            if (newFD == -1)
                {
                    std::cerr << "Error while Accepting on socket or clossing server...\n";
                    continue;
                }
            rx_cmd_thread = std::thread(&tcp_rx_cmd, newFD);
            while (server_active)
                {
                    pps_info_queue->wait_and_pop(new_pps);
                    std::string info("sc=" + std::to_string(new_pps.samplestamp) + "," + "o=" + std::to_string(new_pps.overflow) + "\n");
                    // send call sends the data you specify as second param and it's length as 3rd param, also returns how many bytes were actually sent
                    auto bytes_sent = send(newFD, info.data(), info.length(), 0);
                    if (bytes_sent <= 0)
                        {
                            std::cerr << "Connection terminated...\n";
                            break;
                        }
                }
            close(newFD);
            if (rx_cmd_thread.joinable())
                {
                    rx_cmd_thread.join();
                }
        }

    close(socket_desc);

    if (rx_cmd_thread.joinable())
        {
            rx_cmd_thread.join();
        }

    return 0;
}

bool wait_pps_interrupt(uint64_t *pps_samplestamp, uint32_t *overflow_flag)
{
    struct pollfd fds = {
        .fd = pps_samplestamp_device_descriptor,
        .events = POLLIN,
    };

    bool result = false;

    // enable interrupts
    int reenable = 1;
    write(pps_samplestamp_device_descriptor, reinterpret_cast<void *>(&reenable), sizeof(int));
    int irq_count;
    ssize_t nb;
    // wait for interrupt from PPS IP
    int ret = poll(&fds, 1, 1000);  //1000 ms timeout
    if (ret >= 1)
        {
            nb = read(pps_samplestamp_device_descriptor, &irq_count, sizeof(irq_count));
            if (nb != sizeof(irq_count))
                {
                    std::cerr << "IRQ Read failed to retrieve 4 bytes!\n";
                    std::cerr << "IP module Interrupt number " << irq_count << "\n";
                    return false;
                }
            // read associated counter
            uint32_t low_word = pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_READ_SAMPLE_COUNT_L_REG];
            uint32_t high_word = pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_READ_SAMPLE_COUNT_H_REG];
            *pps_samplestamp = high_word;
            *pps_samplestamp = *pps_samplestamp << 32;
            *pps_samplestamp += low_word;
            // read overflow flag and clear it
            *overflow_flag = pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_READ_OVERFLOW_REG];
            pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_WRITE_CLEAR_OVERFLOW_FLAG] = 1;

            result = true;
        }
    //    else
    //        {
    //            //perror("poll()");
    //            std::cerr << "ERROR: IRQ timeout\n";
    //        }

    //clear interrupt
    if (pps_samplestamp_map_base != NULL)
        {
            pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_WRITE_CLEAR_INTERRUPT_FLAG] = 1;
        }

    return result;
}


bool check_pps_ip()
{
    // only one device of pps samplestamp should be present
    // check FPGA PPS IP and UIO interface
    std::vector<std::string> device_names = FindDeviceByCoreName("pps_samplestamp");
    if (device_names.empty())
        {
            std::cout << "PPS Samplestamp IP core not found!\n";
            return false;
        }
    if ((pps_samplestamp_device_descriptor = open(device_names.at(0).c_str(), O_RDWR | O_SYNC)) == -1)
        {
            std::cout << "Cannot open device UIO " << device_names.at(0).c_str() << "\n";
            return false;
        }
    // constants
    const size_t PAGE_SIZE = 0x10000;
    pps_samplestamp_map_base = reinterpret_cast<volatile unsigned *>(
        mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
            pps_samplestamp_device_descriptor, 0));

    if (pps_samplestamp_map_base == reinterpret_cast<void *>(-1))
        {
            std::cout << "Cannot map the FPGA IP module PPS Samplestamp into memory (UIO dev: " << device_names.at(0).c_str() << ")\n";
            return false;
        }
    else
        {
            std::cout << "FPGA IP module PPS Samplestamp memory successfully mapped (UIO dev: " << device_names.at(0).c_str() << ")\n";
        }

    // sanity check : check version register
    uint32_t readval = pps_samplestamp_map_base[PPS_SAMPLESTAMP_IP_READ_HW_VERSION_REG];
    uint32_t ip_hw_type = (readval & 0xFF00) >> 8;
    uint32_t ip_hw_version = (readval & 0x00FF) >> 8;

    std::cout << "Detected IP PPS Samplestamp with HW Type " << ip_hw_type
              << " rev. " << ip_hw_version << "\n";
    if (ip_hw_type != PPS_SAMPLESTAMP_IP_HW_TYPE)
        {
            std::cout << "The device " << device_names.at(0).c_str() << " does not match the expected HW type" << std::endl;
            return false;
        }
    return true;
}

bool check_dynamicbits_ip()
{
    // may be multiple dynamic bits IP devices for multichannels (e.g. plutosdr with mimo 2x2 enabled).
    // check FPGA AD9361 DYNAMICBITS IP and UIO interface
    std::vector<std::string> device_names = FindDeviceByCoreName("ad9361_dynamicbits");
    if (device_names.empty())
        {
            std::cout << "AD9361 Dynamic Bits selector IP core not found!\n";
            return false;
        }

    for (auto it = std::begin(device_names); it != std::end(device_names); ++it)
        {
            int tmp_dev = open(it->c_str(), O_RDWR | O_SYNC);
            if (tmp_dev == -1)
                {
                    std::cout << "Cannot open device UIO " << it->c_str() << "\n";
                    return false;
                }
            dynamicbits_device_descriptors.push_back(tmp_dev);
            // constants
            const size_t PAGE_SIZE = 0x10000;
            dynamicbits_map_bases.push_back(reinterpret_cast<volatile unsigned *>(
                mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                    dynamicbits_device_descriptors.back(), 0)));

            if (dynamicbits_map_bases.back() == reinterpret_cast<void *>(-1))
                {
                    std::cout << "Cannot map the FPGA IP module AD9361 DYNAMICBITS into memory (UIO dev: " << it->c_str() << ")\n";
                    return false;
                }
            else
                {
                    std::cout << "FPGA IP module AD9361 DYNAMICBITS memory successfully mapped (UIO dev: " << it->c_str() << ")\n";
                }

            // sanity check : check version register
            uint32_t readval = dynamicbits_map_bases.back()[AD9361_DYNAMICBITS_IP_READ_HW_VERSION_REG];
            uint32_t ip_hw_type = (readval & 0xFF00) >> 8;
            uint32_t ip_hw_version = (readval & 0x00FF) >> 8;

            std::cout << "Detected IP AD9361 DYNAMICBITS with HW Type " << ip_hw_type
                      << " rev. " << ip_hw_version << "\n";
            if (ip_hw_type != AD9361_DYNAMICBITS_IP_HW_TYPE)
                {
                    std::cout << "The device " << it->c_str() << " does not match the expected HW type" << std::endl;
                    return false;
                }
        }
    return true;
}


/**
 * \brief This function will daemonize this app
 */
static void daemonize()
{
    pid_t pid = 0;
    int fd;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        {
            exit(EXIT_FAILURE);
        }

    /* Success: Let the parent terminate */
    if (pid > 0)
        {
            exit(EXIT_SUCCESS);
        }

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        {
            exit(EXIT_FAILURE);
        }

    /* Ignore signal sent from child to parent process */
    signal(SIGCHLD, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        {
            exit(EXIT_FAILURE);
        }

    /* Success: Let the parent terminate */
    if (pid > 0)
        {
            exit(EXIT_SUCCESS);
        }

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
        {
            close(fd);
        }

    /* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+");

    /* Try to write PID of daemon to lockfile */
    if (pid_file_name != NULL)
        {
            char str[256];
            pid_fd = open(pid_file_name, O_RDWR | O_CREAT, 0640);
            if (pid_fd < 0)
                {
                    /* Can't open lockfile */
                    exit(EXIT_FAILURE);
                }
            if (lockf(pid_fd, F_TLOCK, 0) < 0)
                {
                    /* Can't lock file */
                    exit(EXIT_FAILURE);
                }
            /* Get current PID */
            sprintf(str, "%d\n", getpid());
            /* Write PID to lockfile */
            write(pid_fd, str, strlen(str));
        }
}

/**
 * \brief Print help for this application
 */
void print_help(void)
{
    printf("\n Usage: %s [OPTIONS]\n\n", app_name);
    printf("  Options:\n");
    printf("   -h --help                 Print this help\n");
    printf("   -d --daemon               Daemonize this application\n");
    printf("   -p --pid_file  filename   PID file used by daemonized app\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    const std::string intro_help(
        std::string("\nPLUTOGNSS Samplestamp and Dynamic Sample Resolution Server is a tool to send the Samplestamp associated to the GNSS PPS rising edge to a remote device over TCP.\n") +
        "Copyright (C) 2022 (see AUTHORS file for a list of contributors)\n" +
        "This program comes with ABSOLUTELY NO WARRANTY;\n" +
        "See COPYING file to see a copy of the General Public License\n \n");

    const std::string version(PLUTOGNSSSTSERVER_VERSION);

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"daemon", no_argument, 0, 'd'},
        {"pid_file", required_argument, 0, 'p'},
        {NULL, 0, 0, 0}};
    int value, option_index = 0;
    char *log_file_name = NULL;
    int start_daemonized = 0;

    app_name = argv[0];

    /* Try to process all command line arguments */
    while ((value = getopt_long(argc, argv, "c:l:t:p:dh", long_options, &option_index)) != -1)
        {
            switch (value)
                {
                case 'p':
                    pid_file_name = strdup(optarg);
                    break;
                case 'd':
                    start_daemonized = 1;
                    break;
                case 'h':
                    print_help();
                    return EXIT_SUCCESS;
                case '?':
                    print_help();
                    return EXIT_FAILURE;
                default:
                    break;
                }
        }

    /* When daemonizing is requested at command line. */
    if (start_daemonized == 1)
        {
            /* It is also possible to use glibc function deamon()
		 * at this point, but it is useful to customize your daemon. */
            daemonize();
        }

    syslog(LOG_INFO, "Started %s", app_name);

    /* Daemon will handle two signals */
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);

    std::cout << "Initializing PLUTOGNSS Samplestamp Server and Dynamic Sample Resolution v" << version << " ... Please wait." << std::endl;


    if (check_pps_ip() == false)
        {
            std::cout << "PLUTOGNSS can not find the required FPGA PPS IP CORE!" << std::endl;
            //return -1;
        }

    if (check_dynamicbits_ip() == false)
        {
            std::cout << "PLUTOGNSS can not find the required FPGA DYNAMIC BITS IP CORE!" << std::endl;
            //return -1;
        }

    pps_info_queue = std::shared_ptr<Concurrent_Queue<pps_info>>(new Concurrent_Queue<pps_info>());

    server_active = true;

    // setup TCP server
    int tcp_port = 10000;

    //start record to file thread
    std::thread tcp_thread;
    tcp_thread = std::thread(&tcp_server_single, tcp_port);

    std::cout << "PLUTOGNSS Samplestamp Server and Dynamic Sample Resolution is listening for TCP connections on port " << tcp_port << " on all network interfaces..." << std::endl;

    // wait loop
    pps_info new_pps;
    while (server_active)
        {
            if (wait_pps_interrupt(&new_pps.samplestamp, &new_pps.overflow))
                {
                    pps_info_queue->push(new_pps);
                }
        }

    std::cout << "Joining TCP thread...\n";
    close(socket_desc);
    //todo: force the detach and kill the thread
    tcp_thread.detach();
    std::cout << "PLUTOGNSS Samplestamp Server and Dynamic Sample Resolution program ended." << std::endl;

    /* Write system log and close it. */
    syslog(LOG_INFO, "Stopped %s", app_name);
    closelog();

    /* Free allocated memory */
    if (log_file_name != NULL) free(log_file_name);
    if (pid_file_name != NULL) free(pid_file_name);

    return EXIT_SUCCESS;
}
