#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/reg.h>



//
// You should use the following functions to print information
// Do not modify these functions
//

// Track virtual environment state
static int env_active = 0;
static char* env_path = NULL;
static char* original_path = NULL;

void print_prompt() {
    if (env_active) {
        printf("(env) sh > ");
    } else {
        printf("sh > ");
    }
    fflush(stdout);
}

void print_invalid_syntax() {
    printf("Invalid Syntax\n");
    fflush(stdout);
}

void print_command_not_found() {
    printf("Command Not Found\n");
    fflush(stdout);
}

void print_execution_error() {
    printf("Execution Error\n");
    fflush(stdout);
}

void print_blocked_syscall(char* syscall_name, int count, ...) {
    va_list args;
    va_start(args, count);
    printf("Blocked Syscall: %s ", syscall_name);
    for (int i = 0; i < count; i++) {
        char* arg = va_arg(args, char*);
        printf("%s ", arg);
    }
    printf("\n");
    fflush(stdout);
}

typedef struct {
    char* data[10][100];
    int count[10];
}ArgvList;

int is_builtin_cmd(char* cmd) {
    return (strcmp(cmd, "exit") == 0 || strcmp(cmd, "cd") == 0 || strcmp(cmd, "env") == 0 || strcmp(cmd, "env-use") == 0 || strcmp(cmd, "env-exit") == 0);
}

int cut_pipe_cmd(char** argv, ArgvList* argv_list) {
	int pipe_num = 0;
	argv_list->count[pipe_num] = 0;
    for (int i = 0; argv[i] != NULL; i++) {
        if (strcmp(argv[i], "|") == 0) {
			argv_list->data[pipe_num][argv_list->count[pipe_num]] = NULL;
            pipe_num += 1;
			argv_list->count[pipe_num] = 0;
        }
		else argv_list->data[pipe_num][argv_list->count[pipe_num]++] = argv[i];
	}
	argv_list->data[pipe_num][argv_list->count[pipe_num]] = NULL;
	return pipe_num;
}

void execute_pipe(ArgvList* argvs, int pipe_num) {
    int pipefd[pipe_num][2];
    int status[pipe_num + 1];
    int i, j;
    
    for (i = 0; i < pipe_num; i++) {
        if (pipe(pipefd[i]) == -1) {
            print_execution_error();
            return;
        }
	}

    pid_t ps[pipe_num + 1];
    for (i = 0; i <= pipe_num; i++) {
        ps[i] = fork();
        if (ps[i] == 0) break;
    }

    if (i <= pipe_num && ps[i] == 0) {
        int stdout_copy_p = dup(STDOUT_FILENO);
        if (i == 0) {   
            dup2(pipefd[0][1], STDOUT_FILENO);
            close(pipefd[0][1]);          
        }
        else if (i== pipe_num) {
            dup2(pipefd[i - 1][0], STDIN_FILENO);
            close(pipefd[i - 1][0]);
        }
        else {
            dup2(pipefd[i - 1][0], STDIN_FILENO);
            close(pipefd[i - 1][0]);
            dup2(pipefd[i][1], STDOUT_FILENO);
            close(pipefd[i][1]);
			}

        for (j = 0; j < pipe_num; j++) {
            close(pipefd[j][0]);
            close(pipefd[j][1]);
        }

        if (execvp(argvs->data[i][0], argvs->data[i]) == -1) {
            if (errno == ENOENT) {
                dup2(stdout_copy_p, STDOUT_FILENO);
                if (is_builtin_cmd(argvs->data[i][0])) {
                    exit(0);
                }
                print_command_not_found();
                exit(127);
            }
            else {
                print_execution_error();
                exit(126);
            }
        }
    }
    else {
        for (i = 0; i < pipe_num; i++) {
            close(pipefd[i][0]);
            close(pipefd[i][1]);
		}
    }
   
    for (i = 0; i <= pipe_num; i++) {
        waitpid(ps[i], &status[i], 0);
        if (WIFSIGNALED(status[i])) {
            print_execution_error();
            return;
        }
        else {
            int code = WEXITSTATUS(status[i]);
            if ((code != 0 && code != 127 && code != 126)) {
                print_execution_error();
            }
        }
    }
}

int is_operator(char* s) {
    if (s == NULL) return 0;
    return (strcmp(s, "|") == 0 || strcmp(s, ">") == 0 ||
        strcmp(s, "<") == 0 || strcmp(s, ">>") == 0);
}

int check_syntax(char** argv) {
    for (int i = 0; argv[i] != NULL; i++) {
        if (strcmp(argv[i], "|") == 0) {
            if (is_operator(argv[i + 1])) return -1;
        }
        if (strcmp(argv[i], ">") == 0) {
            if (is_operator(argv[i + 1])) return -1;
            if (i == 0) return -1;
        }
    }
    return 0;
}

typedef struct {
    char name[32];
    int sys_num;
    int arg_idx[6];
    char arg_value[6][256];
	int arg_count;
}Rule;

typedef struct {
    Rule data[100];
    int count;
}RuleList;

typedef enum { INT, STR, PTR }ArgType;

typedef struct {
    char* name;
    int sys_num;
    int arg_count;
    ArgType type[6];
}Syscall;

Syscall syscall_list[] = {
    {"read", 0, 3, {INT, PTR, INT}},
    {"write", 1, 3, {INT, STR, INT}},
    {"open", 2, 2, {STR, INT, INT}},
    {"pipe", 22, 1, {PTR}},
    {"dup", 32, 1, {INT}},
    {"clone", 56, 5, {INT}},
    {"fork", 57, 0, {}},
    {"execve", 59, 3, {STR, PTR, PTR}},
    {"mkdir", 83, 2, {STR, INT}},
    {"chmod", 90, 2, {STR, INT}},
};

int get_syscall_num(char* name) {
	if (strcmp(name, "read") == 0) return 0;
	if (strcmp(name, "write") == 0) return 1;
	if (strcmp(name, "open") == 0) return 2;
	if (strcmp(name, "pipe") == 0) return 22;
	if (strcmp(name, "dup") == 0) return 32;
	if (strcmp(name, "clone") == 0) return 56;
	if (strcmp(name, "fork") == 0) return 57;
	if (strcmp(name, "execve") == 0) return 59; 
	if (strcmp(name, "mkdir") == 0) return 83;
	if (strcmp(name, "chmod") == 0) return 90;
	return -1;
}

void cut_tails(char* s) {
    while (*s) {
        if (*s == '\r' || *s == '\n') {
            *s = '\0';
            break;
        }
        s++;
    }
}

int load_rules(const char* file_name, RuleList* rules) {
    FILE* file = fopen(file_name, "r");
    if (file == NULL) {
        print_execution_error();
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof(line), file) != NULL) {
		cut_tails(line);
        if (strncmp(line,"deny:",5)!=0) {
            continue;
		}
		char* content = line + 5;
		char* name = strtok(content, " ");
        if (name == NULL) continue;

		rules->data[rules->count].sys_num = get_syscall_num(name);
		strcpy(rules->data[rules->count].name, name);
        rules->data[rules->count].arg_count = 0;
        for(int i= 0; i < 6; i++) {
            rules->data[rules->count].arg_idx[i] = -1;
		}
        
		char* arg = strtok(NULL, "");
        if (arg != NULL) {
            char* current = arg;
            while ((current = strstr(current, "arg")) != NULL) {
                int idx;
                char val[256];
                if (sscanf(current, "arg%d=\"%[^\"]\"", &idx, val) == 2) {
					rules->data[rules->count].arg_idx[idx] = idx;
					strcpy(rules->data[rules->count].arg_value[idx], val);
					rules->data[rules->count].arg_count++;
                }
                else if (sscanf(current, "arg%d=%s", &idx, val) == 2) {
                    rules->data[rules->count].arg_idx[idx] = idx;
                    strcpy(rules->data[rules->count].arg_value[idx], val);
                    rules->data[rules->count].arg_count++;
                }
				char* next = strchr(current, ' ');
                if (next == NULL) break;
				current = next + 1;
            }
        }

        rules->count++;
    }
	fclose(file);
    return 0;
}

void read_remote_str(pid_t pid, unsigned long addr, char* buffer) {
	int i = 0;
	int done = 0;
    while (i < 255 && !done) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (data == -1 && errno != 0) {
            return;
        }
		char* ptr = (char*)&data;
        for (int j = 0; j < sizeof(data); j++) {
            if (i + j > 255) {
                done = 1;
                break;
            }
            buffer[i + j] = ptr[j];
            if (ptr[j] == '\0') {
				done = 1;
                break;
			}
		}
		i += sizeof(data);
    }
	buffer[255] = '\0';
}

void transform_path(pid_t pid, struct user_regs_struct *regs, int sys_num) {
	Syscall *sc = NULL;
    for (int i = 0; i < sizeof(syscall_list) / sizeof(Syscall); i++) {
        if (syscall_list[i].sys_num == sys_num) {
            sc = &syscall_list[i];
            break;
        }
	}

    if (sc == NULL) {
		print_blocked_syscall("unknown", 0);
        return;
    }
    else {
        unsigned long reg_vals[6] = { regs->rdi,regs->rsi,regs->rdx,regs->r10,regs->r8,regs->r9 };
        char store[6][270];
        char* args_ptrs[6];
        for (int i = 0; i < sc->arg_count; i++) {
            switch (sc->type[i])
            {
            case STR:
                char buf[256];
                read_remote_str(pid, reg_vals[i], buf);
				snprintf(store[i], sizeof(store[i]), "\"%s\"", buf);
                break;
            case INT:
                snprintf(store[i], sizeof(store[i]), "%ld", reg_vals[i]);
				break;
            case PTR:
				snprintf(store[i], sizeof(store[i]), "0x%lx", reg_vals[i]);
                break;
            default:
                break;
            }
			args_ptrs[i] = store[i];
        }
        switch (sc->arg_count) {
		case 0: print_blocked_syscall(sc->name, 0); break;
		case 1: print_blocked_syscall(sc->name, 1, args_ptrs[0]); break;
		case 2: print_blocked_syscall(sc->name, 2, args_ptrs[0], args_ptrs[1]); break;
		case 3: print_blocked_syscall(sc->name, 3, args_ptrs[0], args_ptrs[1], args_ptrs[2]); break;
        }
    }
}

void handle_sandbox(pid_t pid, char** argv, RuleList* rules) {
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return;
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    int count = 0;

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
		}

        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            count++;
        }

        if (count % 2 != 0) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                kill(pid, SIGKILL);
                break;
            }

            long syscall_num = regs.orig_rax;
            for (int i = 0; i < rules->count; i++) {
                if (rules->data[i].sys_num == syscall_num) {
                    int blocked = 0;
                    if (rules->data[i].arg_count == 0) {
                        blocked = 1;
                    }
                    else {
						Syscall* sc = NULL;
                        for (int j = 0; j < sizeof(syscall_list) / sizeof(Syscall); j++) {
                            if (syscall_list[j].sys_num == syscall_num) {
                                sc = &syscall_list[j];
                                break;
							}
                        }

                        if (sc != NULL) {
                            unsigned long reg_vals[6] = { regs.rdi,regs.rsi,regs.rdx,regs.r10,regs.r8,regs.r9 };
                            int match = 0;
                            for (int k = 0; k < 6; k++) {
                                int idx = rules->data[i].arg_idx[k];
                                if (idx == -1) continue;
                                unsigned long arg_value = reg_vals[idx];
                                
                                if (sc->type[idx] == STR) {
                                    char arg_str[256];
                                    read_remote_str(pid, arg_value, arg_str);
                                    if (strcmp(arg_str, rules->data[i].arg_value[idx]) == 0) {
                                        match += 1;
                                    }
                                }
                                else {
                                    char arg_str[64];
                                    snprintf(arg_str, sizeof(arg_str), "%ld", arg_value);
                                    if (strcmp(arg_str, rules->data[i].arg_value[idx]) == 0) {
                                        match += 1;
                                    }
                                }           
                            }
                            if (match == rules->data[i].arg_count) {
                                blocked = 1;
                            }
						}

                    }
                    if (blocked) {
                        transform_path(pid, &regs, syscall_num);

                        regs.orig_rax = -1;
                        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

                        kill(pid, SIGKILL);
                        int f_status;
                        while (waitpid(pid, &f_status, 0) > 0) {
                            if (WIFEXITED(f_status) || WIFSIGNALED(f_status)) break;
                            ptrace(PTRACE_CONT, pid, NULL, NULL);
                        }
                        waitpid(pid, NULL, 0);
                        return;
                    }
                }
            }
        }
    }
}


int main() {
    clearenv();

    char npath[1024];
    if (getcwd(npath, sizeof(npath)) == NULL) {
        perror("getcwd");
        exit(1);
    }

    setenv("PATH", "/bin", 1);
    setenv("HOME", npath, 1);
    setenv("PWD", npath, 1);
    setenv("OLDPWD", npath, 1);
    setenv("LANG", "en_US.UTF-8", 1);
    setenv("SH_VERSION", "1.13", 1);

    while (1) {
        print_prompt();
        char message[1024];
        char* argv[100];
        if (fgets(message, sizeof(message), stdin) == NULL) {
            if (feof(stdin)) exit(0);
            break;
        }

        int i = 0;
        char* token = strtok(message, " \t\r\n");
        for (i = 0; i < 99 && token != NULL; i++) {
            argv[i] = token;
            token = strtok(NULL, " \t\r\n");
        }
        argv[i] = NULL;

        if (argv[0] == NULL) {
            continue;
        }

        if (check_syntax(argv) == -1) {
            print_invalid_syntax();
            continue;
		}

        int is_sandbox = 0;
        char* rule_file = NULL;
		char** cmd_argv = argv;
        RuleList rules;
        if (strcmp(argv[0], "sandbox") == 0) {
            if (argv[1] == NULL || argv[2] == NULL) {
                print_invalid_syntax();
                continue;
            }
            is_sandbox = 1;
            rule_file = argv[1];
            cmd_argv = &argv[2];

            rules.count = 0;
            if (load_rules(rule_file, &rules)==-1) continue;
		}

        int pipe_idx = -1;
        for (int i = 0; cmd_argv[i] != NULL; i++) {
            if (strcmp(cmd_argv[i], "||") == 0) {
                print_invalid_syntax();
                pipe_idx = 0;
                break;
            }
            if (strcmp(cmd_argv[i], "|") == 0) {
                if (i == 0 || cmd_argv[i + 1] == NULL) {
                    print_invalid_syntax();
                    pipe_idx = 0;
                    break;
                }
                else if (strcmp(cmd_argv[i + 1], "|") == 0) {
                    print_invalid_syntax();
                    pipe_idx = 0;
                    break;
                }
                pipe_idx = 1;
                break;
            }
        }
        if (pipe_idx != -1) {
            if (pipe_idx == 0) {
                continue;
            }
			ArgvList argvs[10];
            memset(&argvs, 0, sizeof(ArgvList));
			int pipe_num = cut_pipe_cmd(cmd_argv, argvs);
            execute_pipe(argvs, pipe_num);
            continue;
        }

        if (strcmp(cmd_argv[0], "exit") == 0) {
            if (cmd_argv[1] != NULL) {
                print_invalid_syntax();
                continue;
            }
            else {
				return 0;
            }
        }
        else if (strcmp(cmd_argv[0], "cd") == 0) {
            char* target_path = cmd_argv[1];
            char target_path_h[1024];
            if (target_path == NULL || cmd_argv[2] != NULL) {
				print_invalid_syntax();
                continue;
			}
            if (target_path[0] == '~') {
                if (strlen(target_path) == 1) target_path = getenv("HOME");
                else {
                    snprintf(target_path_h, sizeof(target_path_h), "%s%s", getenv("HOME"), target_path + 1);
                    target_path = target_path_h;
                }
            }

            char old_w_path[1024];
            getcwd(old_w_path, sizeof(old_w_path));
            
            if (chdir(target_path) != 0) {
				print_execution_error();
            }
            else {
                char new_w_path[1024];
                getcwd(new_w_path, sizeof(new_w_path));
                setenv("OLDPWD", old_w_path, 1);
                setenv("PWD", new_w_path, 1);
            }
            continue;
        }
        else if (strcmp(cmd_argv[0], "env-use") == 0) {
            if (cmd_argv[1] == NULL || cmd_argv[2] != NULL) {
                print_invalid_syntax();
                continue;
            }
            else {
                if (env_active == 0 && original_path == NULL) {
                    original_path = strdup(getenv("PATH"));
                }
                env_active = 1;

                char* old_path = getenv("PATH");
                char* new_path = malloc(strlen(cmd_argv[1]) + strlen(old_path) + 10);
                sprintf(new_path, "%s/bin:%s", cmd_argv[1], old_path);

                if (setenv("PATH", new_path, 1) != 0) {
                    print_execution_error();
                }

                free(new_path);
                continue;
            }
        }
        else if (strcmp(cmd_argv[0], "env-exit") == 0) {
            if (cmd_argv[1] != NULL) {
                print_invalid_syntax();
                continue;
            }
            if (env_active == 0) {
                continue;
            }
            env_active = 0;

            if (original_path != NULL) {
                if (setenv("PATH", original_path, 1) != 0) {
                    print_execution_error();
                }
                free(original_path);
                original_path = NULL;
            }
            continue;   
        }
        else if (strcmp(cmd_argv[0], "env") == 0) {
            if (cmd_argv[1] != NULL) {
                print_invalid_syntax();
                continue;
            }
            else {
                printf("PATH=%s\n", getenv("PATH"));
                printf("HOME=%s\n", getenv("HOME"));
                printf("PWD=%s\n", getenv("PWD"));
                printf("OLDPWD=%s\n", getenv("OLDPWD"));
                printf("LANG=%s\n", getenv("LANG"));
                printf("SH_VERSION=%s\n", getenv("SH_VERSION"));
                fflush(stdout);
                continue;
            }
        }
        else {
            char* redirect_file = NULL;
            int syntax_error = 0;
            for (int i = 0; cmd_argv[i] != NULL; i++) {
                if (strcmp(cmd_argv[i], "<") == 0 || strcmp(cmd_argv[i], ">>") == 0) {
                    print_invalid_syntax();
                    syntax_error = 1;
                    break;
                }

                if (strcmp(cmd_argv[i], ">") == 0) {
                    if (cmd_argv[i + 1] == NULL || cmd_argv[i + 2] != NULL || i == 0) {
                        print_invalid_syntax();
                        syntax_error = 1;
                        break;
                    }
                    else {
                        redirect_file = cmd_argv[i + 1];
                        cmd_argv[i] = NULL;
                    }
                    break;
                }
            }
            if (syntax_error == 1) continue;

            pid_t pid = fork();
            if (pid == 0) {
                if (is_sandbox) {
                    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                }

                int stdout_copy = -1;
                if (redirect_file != NULL) {
                    int fd = open(redirect_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd == -1) {
                        print_execution_error();
                        exit(1);
                    }
                    stdout_copy = dup(STDOUT_FILENO);
                    if (dup2(fd, STDOUT_FILENO) == -1) {
                        print_execution_error();
                        close(fd);
                        exit(1);
                    }
                    else {
                        close(fd);
                    }
                }

                if (execvp(cmd_argv[0], cmd_argv) == -1) {
                    if (errno == ENOENT) {
                        if (redirect_file != NULL) {
                            dup2(stdout_copy, STDOUT_FILENO);
                            close(stdout_copy);
                        }
                        print_command_not_found();
                        exit(127);
                    }
                    else {
                        print_execution_error();
                        exit(126);
                    }
                }
            }
            else if (pid > 0) {
                if (is_sandbox) {
                    handle_sandbox(pid, cmd_argv, &rules);
                    continue;
                }
                else {
                    int status;
                    waitpid(pid, &status, 0);
                    if (WIFSIGNALED(status)) {
                        print_execution_error();
                    }
                    else if (WIFEXITED(status)) {
                        if (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 127 && WEXITSTATUS(status) != 126) {
                            print_execution_error();
                        }
                    }
                }
            }
            else {
                print_execution_error();
            }
        }
    }
    return 0;
}