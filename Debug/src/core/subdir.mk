################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/core/core.cpp \
../src/core/keystore.cpp \
../src/core/utility.cpp 

OBJS += \
./src/core/core.o \
./src/core/keystore.o \
./src/core/utility.o 

CPP_DEPS += \
./src/core/core.d \
./src/core/keystore.d \
./src/core/utility.d 


# Each subdirectory must supply rules for building sources it contributes
src/core/%.o: ../src/core/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


