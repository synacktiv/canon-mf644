
# Debian package dependency: binutils-arm-none-eabi

all: shellcode_ninja.bin

shellcode_ninja.o: shellcode_ninja.S
	arm-none-eabi-as -EL $< -o $@

shellcode_ninja.bin: shellcode_ninja.o
	arm-none-eabi-objcopy -O binary $< $@

clean:
	rm shellcode_ninja.o shellcode_ninja.bin
