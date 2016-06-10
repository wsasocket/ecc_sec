################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/kernal/alg_cigher_aes128.cpp \
../src/kernal/alg_digital_envelope.cpp \
../src/kernal/alg_hash_MD5.cpp \
../src/kernal/alg_hash_SHA256.cpp \
../src/kernal/configure.cpp 

OBJS += \
./src/kernal/alg_cigher_aes128.o \
./src/kernal/alg_digital_envelope.o \
./src/kernal/alg_hash_MD5.o \
./src/kernal/alg_hash_SHA256.o \
./src/kernal/configure.o 

CPP_DEPS += \
./src/kernal/alg_cigher_aes128.d \
./src/kernal/alg_digital_envelope.d \
./src/kernal/alg_hash_MD5.d \
./src/kernal/alg_hash_SHA256.d \
./src/kernal/configure.d 


# Each subdirectory must supply rules for building sources it contributes
src/kernal/%.o: ../src/kernal/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


