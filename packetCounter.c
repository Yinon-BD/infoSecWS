#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define ACC_ATT "/sys/class/PacketCounterClass/PacketCounterClass_PacketCounterDevice/acc_attr"
#define DROP_ATT "/sys/class/PacketCounterClass/PacketCounterClass_PacketCounterDevice/drop_attr"

unsigned int acc_counter;
unsigned int drop_counter;

int fd1, fd2;
char buf[32];
ssize_t bytes;

void print_summary() {

	fd1 = open(ACC_ATT, O_RDWR);

	if(fd1 == -1){
		perror("failed to open device attribute\n");
		exit(1);
	}

	bytes = read(fd1, buf, sizeof(buf) - 1);
	if(bytes == -1){
		perror("Failed to read accept counter");
		close(fd1);
		exit(1);
	}
	buf[bytes] = '\0';
	sscanf(buf, "%u", &acc_counter);

	close(fd1);

	fd2 = open(DROP_ATT, O_RDWR);

	if(fd2 == -1){
		perror("failed to open device attribute\n");
		exit(1);
	}

	bytes = read(fd2, buf, sizeof(buf) - 1);
	if(bytes == -1){
		perror("Failed to read drop counter");
		close(fd2);
		exit(1);
	}

	buf[bytes] = '\0';
	sscanf(buf, "%u", &drop_counter);

	printf("Firewall Packets Summary:\n");
	printf("Number of accepted packets: %u\n", acc_counter);
	printf("Number of dropped packets: %u\n", drop_counter);
	printf("Total number of packets: %u\n", acc_counter + drop_counter);

	close(fd2);
}

int reset_counters() {

	const char* resetValue = "1\n";

	fd1 = open(ACC_ATT, O_RDWR);

	if(fd1 == -1){
		perror("failed to open device attribute\n");
		return -1;
	}

	bytes = write(fd1, resetValue, sizeof("1\n") - 1);
	if(bytes == -1) {
		perror("Failed to reset accept counter");
		close(fd1);
		return -1;
	}

	close(fd1);

	fd2 = open(DROP_ATT, O_RDWR);

	if(fd2 == -1){
		perror("failed to open device attribute\n");
		return -1;
	}

	bytes = write(fd2, resetValue, sizeof("1\n") - 1);
	if(bytes == -1) {
		perror("Failed to reset drop counter");
		close(fd1);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {

	if(argc > 2) {
		perror("Error: More than 1 argument have been passed.\n");
		exit(1);
	}
	if(argc == 2 && strcmp(argv[1], "1") != 0) {
		perror("Error: The only argument that can be passed is \"1\".\n");
		exit(1);
	}

	if(argc == 1){
		print_summary();
	}

	else {
		if(reset_counters() == -1){
			perror("An Error has occured.\n");
			exit(1);
		}
	}

	return 0;
}
