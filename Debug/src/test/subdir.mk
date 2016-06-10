################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/test/init_key.cpp \
../src/test/main.cpp \
../src/test/test_envelope.cpp \
../src/test/test_keystore.cpp 

OBJS += \
./src/test/init_key.o \
./src/test/main.o \
./src/test/test_envelope.o \
./src/test/test_keystore.o 

CPP_DEPS += \
./src/test/init_key.d \
./src/test/main.d \
./src/test/test_envelope.d \
./src/test/test_keystore.d 


# Each subdirectory must supply rules for building sources it contributes
src/test/%.o: ../src/test/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


