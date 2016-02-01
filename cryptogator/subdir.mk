################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../aes.c \
../cryptogator.c \
../hmac.c \
../rsa.c 

OBJS += \
./aes.o \
./cryptogator.o \
./hmac.o \
./rsa.o 

C_DEPS += \
./aes.d \
./cryptogator.d \
./hmac.d \
./rsa.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


