#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#define PAGE_SIZE 4096
 
/* structure for holding user information */
struct node_user_file_role{
    int uid_ino;
    char *role;
    struct node_user_file_role *next;
};

/* structure for holding role information */
struct node_role{
    char *role;
    char *access;
    int role_id;
    struct node_role *next;
};

/* global variables to access lists */
struct node_user_file_role *list_user;
struct node_user_file_role *list_file;
struct node_role *list_role;

/* function to initialize user/file list */
struct node_user_file_role *list_user_file_role_init(struct node_user_file_role *list){
    
    list = malloc(sizeof(struct node_user_file_role));
    
    if(list == NULL){
        printf("sbrack: Cannot initialize the user/file list\n");
        return NULL;
    }
    else{
        list->uid_ino = 0;
        list->role = NULL;
        list->next = NULL;
    }
    
    return list;
}

/* function to initialize role list */
struct node_role *list_role_init(void){
    
    struct node_role *list = malloc(sizeof(struct node_role));
    
    if(list == NULL){
        printf("sbrack: Cannot initialize the role list\n");
        return NULL;
    }
    else{
        list->role = NULL;
        list->access = NULL;
        list->role_id = 0;
        list->next = NULL;
    }
    
    return list;
}

/* function to add a node_user_file_role to the list */
struct node_user_file_role *add_node_user_file_role(struct node_user_file_role *list, int uid_ino, char *role){
    
    int err = 0;
    struct node_user_file_role *n = NULL, *temp = NULL;

    /* checking if list is initialized or not */
    if(list == NULL){
        err = -EINVAL;
        printf("sbrack: User/file list not initialized: err %d\n", err);
        goto out;
    }

    n = malloc(sizeof(struct node_user_file_role));
    
    if(n == NULL){
        err = -ENOMEM;
        printf("sbrack: Cannot add item to the user/file list: err %d\n", err);
        goto out;
    }

    n->uid_ino = uid_ino;
    n->role = role;
    n->next = NULL;

    if(list->next == NULL){
        /* adding first element */
        list->next = n;
    }
    else{
        /* adding at the head */
        temp = list->next;
        list->next = n;
        n->next = temp;
    }

out:
    if(err != 0)
        return NULL;
    else 
        return list;
}

/* function to add a node_role to the list */
struct node_role *add_node_role(struct node_role *list, char *role, char *access, int role_id){
    
    int err = 0;
    struct node_role *n = NULL, *temp = NULL;

    /* checking if list is initialized or not */
    if(list == NULL){
        err = -EINVAL;
        printf("sbrack: Role list not initialized:err %d\n", err);
        goto out;
    }

    n = malloc(sizeof(struct node_role));
    
    if(n == NULL){
        err = -ENOMEM;
        printf("sbrack: Cannot add item to the role list: err %d\n", err);
        goto out;
    }

    n->role = role;
    n->access = access;
    n->role_id = role_id;
    n->next = NULL;

    if(list->next == NULL){
        /* adding first element */
        list->next = n;
    }
    else{
        /* adding at the head */
        temp = list->next;
        list->next = n;
        n->next = temp;
    }

out:
    if(err != 0)
        return NULL;
    else 
        return list;
}

/* function to delete a node_user_file_role from the list */
struct node_user_file_role *delete_node_user_file_role(struct node_user_file_role *list, int uid_ino){
    
    int err = 0;
    struct node_user_file_role *temp = NULL, *temp_prev = NULL;

    /* checking if list is initialized or not */ 
    if(list == NULL){
        err = -EINVAL;
        printf("sbrack: User/file list not initialized: err %d\n", err);
        goto out;
    }

    temp = list->next;
    while(temp){

        if(temp->uid_ino == uid_ino){

            if(temp_prev == NULL){
                /* deleting from head */ 
                list->next = temp->next;
                temp->next = NULL;
                temp->uid_ino = 0;
                free(temp);
            }

            else{
                /* deleting from elsewhere */
                temp_prev->next = temp->next;
                temp->next = NULL;
                temp->uid_ino = 0;
                free(temp);
            }

            break;
        }

        if(temp){
            temp_prev = temp;
            temp = temp->next;
        }
    }

out:
    if(err != 0)
        return NULL;
    else 
        return list;
}

/* function to delete a node_role from the list */
struct node_role *delete_node_role(struct node_role *list, int role_id){
    
    int err = 0;
    struct node_role *temp = NULL, *temp_prev = NULL;

    /* checking if list is initialized or not */ 
    if(list == NULL){
        err = -EINVAL;
        printf("sbrack: Role list not initialized: err %d\n", err);
        goto out;
    }

    temp = list->next;
    while(temp){

        if(temp->role_id == role_id){

            if(temp_prev == NULL){
                /* deleting from head */ 
                list->next = temp->next;
                temp->next = NULL;
                temp->role_id = 0;
                free(temp);
            }

            else{
                /* deleting from elsewhere */
                temp_prev->next = temp->next;
                temp->next = NULL;
                temp->role_id = 0;
                free(temp);
            }

            break;
        }

        if(temp){
            temp_prev = temp;
            temp = temp->next;
        }
    }

out:
    if(err != 0)
        return NULL;
    else 
        return list;
}

/* function to print the user/file list */
void print_user_file_role_list(struct node_user_file_role *list, int user_file){
    struct node_user_file_role *temp = NULL;
    temp = list->next;
    while(temp){
        if(user_file == 0)
            printf("sbrack: UID: %d, Role: %s\n", temp->uid_ino, temp->role);
        else
            printf("sbrack: Inode Number: %d, Role: %s\n", temp->uid_ino, temp->role);
            
        if(temp)
            temp = temp->next;
    }
}

/* function to print the role list */
void print_role_list(struct node_role *list){
    struct node_role *temp = NULL;
    temp = list->next;
    while(temp){
        printf("sbrack: Role ID: %d, Role: %s, Access: %s\n", temp->role_id, temp->role, temp->access);
    
        if(temp)
            temp = temp->next;
    }
}

/* function to find a user/file node */
struct node_user_file_role *find_node_user_file_role(struct node_user_file_role *list, int uid_ino){
    struct node_user_file_role *temp = NULL;
    temp = list->next;
    while(temp){
        
        if(temp->uid_ino == uid_ino)
            goto out;
    
        if(temp)
            temp = temp->next;
    }
    temp = NULL;

out:    
    return temp;
}

/* function to find a role node */
struct node_role *find_node_role(struct node_role *list, int role_id){
    struct node_role *temp = NULL;
    temp = list->next;
    while(temp){
        
        if(temp->role_id == role_id)
            goto out;
    
        if(temp)
            temp = temp->next;
    }
    
    temp = NULL;

out:    
    return temp;
}

/* function to remove a user/file list */
void user_file_role_list_exit(struct node_user_file_role *list){

    struct node_user_file_role *temp = NULL, *free_temp = NULL;
    if(list->next != NULL){
        temp = list->next;
        while(temp){
			free_temp = temp;
			
			if (temp)
                temp = temp->next;
				
            free_temp->uid_ino = 0;
            free(free_temp->role);
            
        }
    }
    list = NULL;
    free(list);
}

/* function to remove a role list */
void role_list_exit(struct node_role *list){

    struct node_role *temp = NULL, *free_temp = NULL;
    if(list->next != NULL){
        temp = list->next;
        while(temp){
			free_temp = temp;
			if (temp)
                temp = temp->next;
				
            free_temp->role_id = 0;
            free(free_temp->role);
            free(free_temp->access);       
        }
    }
    list = NULL;
    free(list);
}

/* function to parse file and polulate user list*/
int parse_user_file_role_buf(char *buf, int user_file){

    char *c = NULL, *line = NULL, *label = NULL, *temp_line = NULL, *role = NULL;
    int len = 0, oper = 0, err = 0, uid_ino = 0;

    while(1){
        c = strsep(&buf, "\n");
        len = (strlen(c)*sizeof(char)) + 1;
        if(c == NULL || len == 1)
            break;
        line = malloc(len);
        memset(line, 0, len);
        if(line == NULL){

            printf("sbrack: Cannot allocate memory to parse user/file configuration\n");
            err = -ENOMEM;
            goto out;
        }
        strncpy(line, c, len);

        temp_line = line;        
        while(1){
            oper++;
            c = strsep(&line, ",");
            len = (strlen(c)*sizeof(char)) + 1;            
            if(c == NULL || len == 1)
                break;
            label = malloc(len);
            if(label == NULL){

                printf("sbrack: Cannot allocate memory to parse user/file configuration\n");
                err = -ENOMEM;
                goto out;
            }

            strncpy(label, c, len);
            if(oper == 1){
                uid_ino = atoi(label);
                free(label);
            }
            else if(oper == 2){
                role = label;
            }
        }
        free(temp_line);
        oper = 0;
        if(user_file == 0)
            list_user = add_node_user_file_role(list_user, uid_ino, role);
        else
            list_file = add_node_user_file_role(list_file, uid_ino, role);
    }

out:
    return err;
}

/* function to parse file and polulate role list*/
int parse_role_buf(char *buf){

    char *c = NULL, *line = NULL, *label = NULL, *temp_line = NULL, *role = NULL, *access = NULL;
    int len = 0, oper = 0, err = 0, role_id = 0;

    while(1){
        c = strsep(&buf, "\n");
        len = (strlen(c)*sizeof(char)) + 1;
        if(c == NULL || len == 1)
            break;
        line = malloc(len);
        memset(line, 0, len);
        if(line == NULL){

            printf("sbrack: Cannot allocate memory to parse role configuration\n");
            err = -ENOMEM;
            goto out;
        }
        strncpy(line, c, len);

        temp_line = line;        
        while(1){
            oper++;
            c = strsep(&line, ",");
            len = (strlen(c)*sizeof(char)) + 1;            
            if(c == NULL || len == 1)
                break;
            label = malloc(len);
            if(label == NULL){

                printf("Cannot allocate memory to parse role configuration\n");
                err = -ENOMEM;
                goto out;
            }

            strncpy(label, c, len);
            if(oper == 1){
                role_id = atoi(label);
                free(label);
            }
            else if(oper == 2){
                role = label;
            }
            else if(oper == 3){
                access = label;
            }
        }
        free(temp_line);
        oper = 0;
        list_role = add_node_role(list_role, role, access, role_id);
    }

out:
    return err;
}

/* function to read file*/
int read_file(const char *filename, void *buf, int len)
{
    int fd, bytes;

    fd = open(filename,  O_RDONLY);
        
    if(fd < 0){
        printf("sbrack: error opening config file for reading err: %d\n", errno);
        bytes = -errno;
        goto out;
    }
        
    bytes = read(fd, buf, len);

    close(fd);

out:
    return bytes;
}

/* function to write user/file configuration file*/
int write_user_file_role_file(const char *filename, struct node_user_file_role *list)
{
    int bytes;
    FILE *file;
    struct node_user_file_role *temp;

    file = fopen(filename, "w");    
    
    if(file == NULL){
        printf("sbrack: Error opening user/file config for writing file err: %d\n", errno);
        bytes = -errno;
        goto out;
    }

    temp = list->next;
        
    while(temp){
        bytes = fprintf (file, "%d,%s,\n", temp->uid_ino, temp->role );
        if (temp)
            temp = temp->next;
    }

    fclose(file);
out:
    return bytes;
}

/* function to write role file*/
int write_role_file(const char *filename, struct node_role *list)
{
    int bytes;
    FILE *file;
    struct node_role *temp;

    file = fopen(filename, "w");    
    
    if(file == NULL){
        printf("sbrack: Error opening role config for writing file err: %d\n", errno);
        bytes = -errno;
        goto out;
    }

    temp = list->next;
        
    while(temp){
        bytes = fprintf (file, "%d,%s,%s,\n", temp->role_id, temp->role, temp->access);
        if (temp)
            temp = temp->next;
    }

    fclose(file);
out:
    return bytes;
}

void main(){

    char *buf = NULL, *temp_buf = NULL, *role = NULL, scan_role[50], *access_temp = NULL, *access = NULL;
    int bytes = 0, choice, role_id = 0, uid_ino = 0, del_role = 0;
    struct node_user_file_role *user_temp = NULL;
    struct node_role *role_temp = NULL, *role_edit = NULL;
    
    /* reading user config file */
    buf = malloc(PAGE_SIZE);
    memset(buf, 0, PAGE_SIZE);
    bytes = read_file("/etc/user_role", buf, PAGE_SIZE);
    
    temp_buf = buf;

    if(bytes < 0){
        printf("sbrack: User configuration file cannot be open. err: %d\n", bytes);    
        goto free_buf;
    }
    else{
        list_user = list_user_file_role_init(list_user);    

        if(list_user == NULL)
            goto free_buf;
    
        parse_user_file_role_buf(buf, 0);
    }

    buf = temp_buf;
    /* reading file config file */
    memset(buf, 0, PAGE_SIZE);
    bytes = read_file("/etc/file_role", buf, PAGE_SIZE);
    
    if(bytes < 0){
        printf("sbrack: File configuration file cannot be open. err: %d\n", bytes);    
        goto free_user_list;
    }
    else{
        list_file = list_user_file_role_init(list_file);    

        if(list_file == NULL)
            goto free_user_list;
    
        parse_user_file_role_buf(buf, 1);
    }

     buf = temp_buf;     
    /* reading role config file */
    memset(buf, 0, PAGE_SIZE);
    bytes = read_file("/etc/role_rule", buf, PAGE_SIZE);

    if(bytes < 0){
        printf("sbrack: Role configuration file cannot be open. err: %d\n", bytes);    
        goto free_file_list;
    }
    else{
        list_role = list_role_init();    

        if(list_role == NULL)
            goto free_file_list;
    
        parse_role_buf(buf);
    }
    
    while(1){
        user_temp = NULL;
        printf("************** User Role Add/Modify **************\n");
        printf("1) Add user\n");
        printf("2) Change user role\n");
        printf("3) Delete user\n");
        printf("4) Add file\n");
        printf("5) Change file role\n");
        printf("6) Delete file\n");
        printf("7) Add role/rules\n");
        printf("8) Edit role/rules\n");
        printf("9) Delete role/rules\n");
		printf("10) Print all users\n");
        printf("11) Print all files\n");
        printf("12) Print all roles\n");
        printf("13) Exit\n");
        printf("***************************************************\n");
        
        scanf("%d", &choice);

        switch(choice){
            case 1:
            printf("Enter UID\n" );
            scanf("%d", &uid_ino);

            if(find_node_user_file_role(list_user,uid_ino)){
                printf("sbrack: User already exists. Please retry\n");
                break;    
            }

            printf("Enter Role ID\n");
            print_role_list(list_role);
            scanf("%d", &role_id);
            role_temp = find_node_role(list_role, role_id);
            if(role_temp != NULL){
                role = malloc(strlen(role_temp->role));
                strcpy(role,role_temp->role);
                list_user = add_node_user_file_role(list_user, uid_ino, role);
            }
            else{
                printf("sbrack: Wrong choice entered. Please retry\n");
                break;
            }
            printf("sbrack: User added\n");
            break;
             
            case 2:
            printf("Enter UID\n" );
            scanf("%d", &uid_ino);
            user_temp = find_node_user_file_role(list_user,uid_ino);
            
            if(user_temp == NULL){
                printf("sbrack: User doesn't exists. Please retry\n");
                break;    
            }
            
            printf("Enter Role ID\n");
            print_role_list(list_role);
            scanf("%d", &role_id);
            role_temp = find_node_role(list_role, role_id);
            if(role_temp != NULL){
                free(user_temp->role);
                role = malloc(strlen(role_temp->role));
                strcpy(role,role_temp->role);
                user_temp->role = role;
            }
            else{
                printf("sbrack: Wrong choice entered. Please retry\n");
                break;
            }
            printf("sbrack: Role changed\n");
            break;
            
            case 3:
            printf("Enter UID\n" );
            scanf("%d", &uid_ino);
            if(find_node_user_file_role(list_user,uid_ino)){
                list_user = delete_node_user_file_role(list_user, uid_ino);    
                printf("User Deleted\n");
            }    
            else
                printf("sbrack: UID not found. Please retry\n");        
            break;
            
            case 4:
            printf("Enter Inode Number\n" );
            scanf("%d", &uid_ino);

            if(find_node_user_file_role(list_file,uid_ino)){
                printf("sbrack: File already exists. Please retry\n");
                break;    
            }

            printf("Enter Role ID\n");
            print_role_list(list_role);
            scanf("%d", &role_id);
            role_temp = find_node_role(list_role, role_id);
            if(role_temp != NULL){
                role = malloc(strlen(role_temp->role));
                strcpy(role,role_temp->role);
                list_file = add_node_user_file_role(list_file, uid_ino, role);
            }
            else{
                printf("sbrack: Wrong choice entered. Please retry\n");
                break;
            }
            printf("sbrack: File added\n");
            break;

            case 5:
            printf("Enter Inode Number\n" );
            scanf("%d", &uid_ino);
            user_temp = find_node_user_file_role(list_file,uid_ino);
            
            if(user_temp == NULL){
                printf("sbrack: File doesn't exists. Please retry\n");
                break;    
            }
            
            printf("Enter Role ID\n");
            print_role_list(list_role);
            scanf("%d", &role_id);
            role_temp = find_node_role(list_role, role_id);
            if(role_temp != NULL){
                free(user_temp->role);
                role = malloc(strlen(role_temp->role));
                strcpy(role,role_temp->role);
                user_temp->role = role;
            }
            else{
                printf("sbrack: Wrong choice entered. Please retry\n");
                break;
            }
            printf("sbrack: File changed\n");
            break;

            case 6:
              printf("Enter Inode Number\n" );
            scanf("%d", &uid_ino);
            if(find_node_user_file_role(list_file,uid_ino)){
                list_file = delete_node_user_file_role(list_file, uid_ino);    
                printf("File Deleted\n");
            }    
            else
                printf("sbrack: UID not found. Please retry\n");        
            break;
            
            case 7:
            printf("Enter Role ID\n" );
            scanf("%d", &role_id);

            if(find_node_role(list_role,role_id)){
                printf("sbrack: Role already exists. Please retry\n");
                break;    
            }
            
            printf("Enter Role\n");
            scanf("%s", scan_role);
            role = malloc(strlen(scan_role));
            strcpy(role,scan_role);
            access_temp = malloc(500);
            memset(access_temp, 0, 500);
            if(list_role->next){
                role_temp = list_role->next;
                while(role_temp){
                
                    printf("Permit access to %s. Press Y/N\n", role_temp->role);
                    memset(scan_role, 0, 50);
                    scanf("%s", scan_role);
                    if(strstr(scan_role, "Y") != NULL){
                        strcat(access_temp, role_temp->role);
                        strcat(access_temp, "|");
                    }
                    if(role_temp)
                        role_temp = role_temp->next;
                }

            }
            access = malloc((strlen(access_temp)+strlen(role)));
            memset(access, 0, (strlen(access_temp)+strlen(role)));
            strcat(access, access_temp);
            free(access_temp);
            strcat(access, role);
            list_role = add_node_role(list_role, role, access, role_id);
            printf("sbrack: Role added\n");
            break;
            
            case 8:
            printf("Enter Role ID\n" );
            scanf("%d", &role_id);
            
            role_edit = find_node_role(list_role,role_id);
            if(role_edit == NULL){
                printf("sbrack: Role doesn't exists. Please retry\n");
                break;    
            }
            
            access_temp = malloc(500);
            memset(access_temp, 0, 500);
            if(list_role->next){
                role_temp = list_role->next;
                while(role_temp){
                    
                    if(role_temp != role_edit){
                        printf("Permit access to %s. Press Y/N\n", role_temp->role);
                        memset(scan_role, 0, 50);
                        scanf("%s", scan_role);
                        if(strstr(scan_role, "Y") != NULL){
                            strcat(access_temp, role_temp->role);
                            strcat(access_temp, "|");
                        }
                    }
                    
                    if(role_temp)
                        role_temp = role_temp->next;
                }

            }
            access = malloc((strlen(access_temp)+strlen(role_edit->role)));
            memset(access, 0, (strlen(access_temp)+strlen(role_edit->role)));
            strcat(access, access_temp);
            free(access_temp);
            strcat(access, role_edit->role);
            free(role_edit->access);
            role_edit->access = access;
            printf("sbrack: Role edited\n");
            break;             
            
			case 9:
            printf("Enter Role ID\n" );
            scanf("%d", &role_id);
            
            role_edit = find_node_role(list_role,role_id);
            if(role_edit == NULL){
                printf("sbrack: Role doesn't exists. Please retry\n");
                break;    
            }
			
            del_role = 0;
			
			if(list_user->next){
				user_temp = list_user->next;
				while(user_temp){
					
					if(strcmp(user_temp->role, role_edit->role) == 0){
						del_role = -1;
						break;
					}
					if(user_temp)
						user_temp = user_temp->next;
				}
			}
			
			if(list_file->next && (del_role != -1)){
				user_temp = list_file->next;
				while(user_temp){
					
					if(strcmp(user_temp->role, role_edit->role) == 0){
						del_role = -1;
						break;
					}
					if(user_temp)
						user_temp = user_temp->next;
				}
			}
			
			if(del_role == 0){
				delete_node_role(list_role, role_id);
				printf("sbrack: Role deleted\n");
			}
			else
				printf("sbrack: Role in use. Cannot delete\n");
            break;
			
            case 10:        
            print_user_file_role_list(list_user, 0);
            break;

            case 11:        
            print_user_file_role_list(list_file, 1);
            break;

            case 12:        
            print_role_list(list_role);
            break;

            case 13:
            goto exit;

            default:
            printf("sbrack: Wrong choice entered. Please retry\n");
           }
    }
exit:
    write_user_file_role_file("/etc/user_role", list_user);
    write_user_file_role_file("/etc/file_role", list_file);
    write_role_file("/etc/role_rule", list_role);
free_role_list:
    role_list_exit(list_role);
free_file_list:
    user_file_role_list_exit(list_file);    
free_user_list:
    user_file_role_list_exit(list_user);
free_buf:
    free(temp_buf);
}