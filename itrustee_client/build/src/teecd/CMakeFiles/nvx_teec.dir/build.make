# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /data/hz_data/github/test_kp_tee/itrustee_client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /data/hz_data/github/test_kp_tee/itrustee_client/build

# Include any dependencies generated for this target.
include src/teecd/CMakeFiles/nvx_teec.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.make

# Include the progress variables for this target.
include src/teecd/CMakeFiles/nvx_teec.dir/progress.make

# Include the compile flags for this target's objects.
include src/teecd/CMakeFiles/nvx_teec.dir/flags.make

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o: src/teecd/CMakeFiles/nvx_teec.dir/flags.make
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o: /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_api.c
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o: src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o -MF CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o.d -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o -c /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_api.c

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.i"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_api.c > CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.i

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.s"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_api.c -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.s

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o: src/teecd/CMakeFiles/nvx_teec.dir/flags.make
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o: /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_ext_api.c
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o: src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o -MF CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o.d -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o -c /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_ext_api.c

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.i"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_ext_api.c > CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.i

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.s"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_ext_api.c -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.s

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o: src/teecd/CMakeFiles/nvx_teec.dir/flags.make
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o: /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_app_load.c
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o: src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o -MF CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o.d -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o -c /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_app_load.c

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.i"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_app_load.c > CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.i

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.s"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_app_load.c -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.s

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o: src/teecd/CMakeFiles/nvx_teec.dir/flags.make
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o: /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_socket.c
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o: src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o -MF CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o.d -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o -c /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_socket.c

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.i"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_socket.c > CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.i

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.s"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_client_socket.c -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.s

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o: src/teecd/CMakeFiles/nvx_teec.dir/flags.make
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o: /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_load_sec_file.c
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o: src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o -MF CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o.d -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o -c /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_load_sec_file.c

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.i"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_load_sec_file.c > CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.i

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.s"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_load_sec_file.c -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.s

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o: src/teecd/CMakeFiles/nvx_teec.dir/flags.make
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o: /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_session_pool.c
src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o: src/teecd/CMakeFiles/nvx_teec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o -MF CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o.d -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o -c /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_session_pool.c

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.i"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_session_pool.c > CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.i

src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.s"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /data/hz_data/github/test_kp_tee/itrustee_client/src/libteec_vendor/tee_session_pool.c -o CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.s

# Object files for target nvx_teec
nvx_teec_OBJECTS = \
"CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o" \
"CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o" \
"CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o" \
"CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o" \
"CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o" \
"CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o"

# External object files for target nvx_teec
nvx_teec_EXTERNAL_OBJECTS =

src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_api.c.o
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_ext_api.c.o
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_app_load.c.o
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_client_socket.c.o
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_load_sec_file.c.o
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/__/libteec_vendor/tee_session_pool.c.o
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/build.make
src/teecd/libnvx_teec.so: /usr/lib64/libnvx_boundscheck.so
src/teecd/libnvx_teec.so: src/teecd/CMakeFiles/nvx_teec.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/data/hz_data/github/test_kp_tee/itrustee_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking C shared library libnvx_teec.so"
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/nvx_teec.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/teecd/CMakeFiles/nvx_teec.dir/build: src/teecd/libnvx_teec.so
.PHONY : src/teecd/CMakeFiles/nvx_teec.dir/build

src/teecd/CMakeFiles/nvx_teec.dir/clean:
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd && $(CMAKE_COMMAND) -P CMakeFiles/nvx_teec.dir/cmake_clean.cmake
.PHONY : src/teecd/CMakeFiles/nvx_teec.dir/clean

src/teecd/CMakeFiles/nvx_teec.dir/depend:
	cd /data/hz_data/github/test_kp_tee/itrustee_client/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /data/hz_data/github/test_kp_tee/itrustee_client /data/hz_data/github/test_kp_tee/itrustee_client/src/teecd /data/hz_data/github/test_kp_tee/itrustee_client/build /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd /data/hz_data/github/test_kp_tee/itrustee_client/build/src/teecd/CMakeFiles/nvx_teec.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/teecd/CMakeFiles/nvx_teec.dir/depend
