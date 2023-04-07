# Copyright (C) 2021 J. Arribas and C. Fernandez-Prades. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name GNSS-SDR-SIM nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# This file is part of PLUTOGNSS

add_executable(plutognssstserver ${CMAKE_CURRENT_SOURCE_DIR}/stserver.cc ${CMAKE_SOURCE_DIR}/src/libs/uio_helper.c)

target_link_libraries(plutognssstserver
    PUBLIC
        plutognsslibs
        Threads::Threads
        ${Boost_LIBRARIES}
)

target_include_directories(plutognssstserver
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/libs
        ${Boost_INCLUDE_DIR}
)

target_compile_definitions(plutognssstserver PRIVATE -DPLUTOGNSSTEST_VERSION="${VERSION}")


add_custom_command(TARGET plutognssstserver
    POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plutognssstserver>
        ${CMAKE_SOURCE_DIR}/install/$<TARGET_FILE_NAME:plutognssstserver>
)

install(TARGETS plutognssstserver
    RUNTIME DESTINATION bin
    COMPONENT "plutognssstserver"
)
