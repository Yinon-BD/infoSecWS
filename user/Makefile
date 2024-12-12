OBJECTS = UserParser.c UserLogOperations.c UserRulesOperations.c

all: $(OBJECTS)
	gcc -O3 -Wall -std=c11 -o main $(OBJECTS)
clean:
	$(RM) main