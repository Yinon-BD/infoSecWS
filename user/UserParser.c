#include "UserParser.h"
#include "UserRulesOperations.h"
#include "UserLogOperations.h"

int main(int argc, char** argv) {
    if(argc == 1){
        printf("No arguments provided\n");
        return 1;
    }
    if(argc == 2){
        if(strcmp(argv[1], "show_rules") == 0){
            if(show_rules() == -1){
                printf("Error: show_rules failed\n");
                return 1;
            }
            return 0;
        }
        if(strcmp(argv[1], "show_log") == 0){
            if(show_log() == -1){
                printf("Error: show_log failed\n");
                return 1;
            }
            return 0;
        }
        if(strcmp(argv[1], "clear_log") == 0){
            if(clear_log() == -1){
                printf("Error: clear_log failed\n");
                return 1;
            }
            return 0;
        }
        printf("Invalid arguments\n");
        return 1;
    }
    if(argc == 3){
        if(strcmp(argv[1], "load_rules") == 0){
            if(load_rules(argv[2]) == -1){
                printf("Error: load_rules failed\n");
                return 1;
            }
            return 0;
        }
        printf("Invalid arguments\n");
        return 1;
    }
    printf("too many arguments\n");
    return 1;
}