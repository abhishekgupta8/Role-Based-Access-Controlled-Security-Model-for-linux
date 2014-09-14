#include <linux/string.h>
#include <linux/init.h> 
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/stat.h>

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* structure to store user information */
struct node_user_file_role{
    int uid_ino;
    char *role;
    struct node_user_file_role *next;
};

/* structure to store role information */
struct node_role{
    int role_id;
    char *role;
    char *access;
    struct node_role *next;
};

/* global variables to access lists */
struct node_user_file_role *user_list;
struct node_user_file_role *file_list;
struct node_role *role_list;

/* function to initialize user/file list */
struct node_user_file_role *user_file_list_init(struct node_user_file_role *list){
    
    list = kmalloc(sizeof(struct node_user_file_role), GFP_KERNEL);
    
    if(list == NULL){
        printk("sbrack: cannot initialize the user list\n");
        return ERR_PTR(ENOMEM);
    }
    else{
        list->uid_ino = 0;
        list->role = NULL;
        list->next = NULL;
    }
    
    return list;
}

/* function to initialize role list */
struct node_role *role_list_init(void){
    
    struct node_role *list = kmalloc(sizeof(struct node_role), GFP_KERNEL);
    
    if(list == NULL){
        printk("sbrack: cannot initialize the role list\n");
        return ERR_PTR(ENOMEM);
    }
    else{
        list->role_id = 0;
        list->role = NULL;
        list->access = NULL;
        list->next = NULL;
    }
    
    return list;
}

/* function to add a node to the user/file list */
struct node_user_file_role *add_node_user_file_role(struct node_user_file_role *list, int uid_ino, char *role){
    
    int err = 0;
    struct node_user_file_role *n = NULL, *temp = NULL;

    /* checking if list is initialized or not */
    if(list == NULL){
        err = -EINVAL;
        printk("sbrack: list not initialized for user/file:err %d\n", err);
        goto out;
    }

    n = kmalloc(sizeof(struct node_user_file_role), GFP_KERNEL);
    
    if(n == NULL){
        err = -ENOMEM;
        printk("sbrack: cannot add item to the user/file list:err %d\n", err);
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
        return ERR_PTR(err);
    else 
        return list;
}

/* function to add a node to the role list */
struct node_role *add_node_role(struct node_role *list, int role_id, char *role, char *access){
    
    int err = 0;
    struct node_role *n = NULL, *temp = NULL;

    /* checking if list is initialized or not */
    if(list == NULL){
        err = -EINVAL;
        printk("sbrack: list not initialized for role:err %d\n", err);
        goto out;
    }

    n = kmalloc(sizeof(struct node_role), GFP_KERNEL);
    
    if(n == NULL){
        err = -ENOMEM;
        printk("sbrack: cannot add item to the role list:err %d\n", err);
        goto out;
    }

    n->role_id = role_id;
    n->role = role;
    n->access = access;
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
        return ERR_PTR(err);
    else 
        return list;
}

/* function to delete a node_user_file_role from the user/file list */
struct node_user_file_role *delete_node_user_file_role(struct node_user_file_role *list, int uid_ino){
    
    int err = 0;
    struct node_user_file_role *temp = NULL, *temp_prev = NULL;

    /* checking if list is initialized or not */ 
    if(list == NULL){
        err = -EINVAL;
        printk("sbrack: User/file list not initialized: Cannot delete. err %d\n", err);
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
                kfree(temp);
            }

            else{
                /* deleting from elsewhere */
                temp_prev->next = temp->next;
                temp->next = NULL;
                temp->uid_ino = 0;
                kfree(temp);
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
        return ERR_PTR(err);
    else 
        return list;
}

/* function to print the user/file list */
void print_user_file_role_list(struct node_user_file_role *list){
    struct node_user_file_role *temp = NULL;

    if(list == NULL){
        printk("sbrack: User list is not initialized. Cannot print.\n");
        return;
    }

    temp = list->next;
    while(temp){
        printk("sbrack: UID: %d, Role: %s\n", temp->uid_ino, temp->role);
    
        if(temp)
            temp = temp->next;
    }
}

/* function to print the role list */
void print_role_list(struct node_role *list){
    struct node_role *temp = NULL;

    if(list == NULL){
        printk("sbrack: Role list is not initialized. Cannot print.\n");
        return;
    }

    temp = list->next;
    while(temp){
        printk("sbrack: Role ID: %d, Role: %s, Access: %s\n", temp->role_id, temp->role, temp->access);
    
        if(temp)
            temp = temp->next;
    }
}

/* function to find a user/file node */
struct node_user_file_role *find_user_file_role_node(struct node_user_file_role *list, int uid_ino){
    struct node_user_file_role *temp = NULL;

    if(list == NULL){
        printk("sbrack: User list is not initialized. Cannot find.\n");
        return temp;
    }

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
struct node_role *find_user_role(struct node_role *list, int role_id){
    struct node_role *temp = NULL;

    if(list == NULL){
        printk("sbrack: Role list is not initialized. Cannot find.\n");
        return temp;
    }

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
void user_list_file_role_exit(struct node_user_file_role *list){

    struct node_user_file_role *temp = NULL, *free_temp = NULL;

    if(list == NULL){
        printk("sbrack: User/file list is not initialized. Cannot delete list.\n");
        return;
    }

    temp = list->next;
    while(temp){
        free_temp = temp;

        if (temp)
            temp = temp->next;

        free_temp->uid_ino = 0;
        kfree(free_temp->role);
    }

    kfree(list);
}

/* function to remove a role list */
void role_list_exit(struct node_role *list){

    struct node_role *temp = NULL, *free_temp = NULL;

    if(list == NULL){
        printk("sbrack: Role list is not initialized. Cannot delete list.\n");
        return;
    }

    temp = list->next;
    while(temp){
        free_temp = temp;
        
        if (temp)
            temp = temp->next;
            
        free_temp->role_id = 0;
        kfree(free_temp->role);
        kfree(free_temp->access);
        
    }

    kfree(list);
}

/* function to read file*/
int read_file(const char *filename, void *buf, int len)
{
    struct file *filp;
    struct kstat stat;
    mm_segment_t oldfs;
    int bytes, file_stat;

    /* turning off address translation */
    oldfs = get_fs();
    set_fs(KERNEL_DS);

    /* checking if file is empty */
    file_stat = vfs_stat(filename, &stat);

    if(file_stat<0){
        set_fs(oldfs);
        printk("sbrack: Configuration file doesn't exist.\n");    
        return -ENOENT;
    }

    if(stat.size==0){
        set_fs(oldfs);
        printk("sbrack: Configuration file is null.\n");    
        return -ENODATA;
    }

    filp = filp_open(filename, O_RDONLY, 0);
        
    if(IS_ERR(filp)){
        set_fs(oldfs);
        printk("sbrack: Configuration file cannot be open err: %d.\n", (int)PTR_ERR(filp));    
        return (int)PTR_ERR(filp);
    }
        
    bytes = filp->f_op->read(filp, buf, len, &filp->f_pos);

    set_fs(oldfs);
    filp_close(filp, NULL);

    return bytes;
}

/* function to write file using linked list*/
int write_file(struct node_user_file_role *list)
{
    mm_segment_t oldfs;
    int ret = 0;
    struct file *filp;
    char *buf = NULL;
    struct node_user_file_role *temp = NULL;
    
    if(list == NULL){
        printk("sbrack: list is not initialized\n");
        return -EINVAL;
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    
    filp = filp_open("/etc/file_role", O_WRONLY | O_TRUNC, 0);
    
    if(IS_ERR(filp)){
        set_fs(oldfs);
        printk("sbrack: File role mapping file cannot be open err: %d.\n", (int)PTR_ERR(filp));    
        return (int)PTR_ERR(filp);
    }
    
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    
    temp = list->next;

    while(temp){
        memset(buf, 0, PAGE_SIZE);
        sprintf(buf, "%d,%s,\n", temp->uid_ino, temp->role);
        ret = vfs_write(filp, buf, strlen(buf), &filp->f_pos);
    
        if(temp)
            temp = temp->next;
    }
    
    kfree(buf);
    set_fs(oldfs);
    filp_close(filp, NULL);

    return ret;
}

/* function to parse file and polulate user/file list*/
int parse_user_file_role_buf(char *buf, int user_file){

    char *c = NULL, *line = NULL, *label = NULL, *temp_line = NULL, *role = NULL;
    int len = 0, oper = 0, err = 0, uid_ino = 0;

    while(1){
        c = strsep(&buf, "\n");
        len = (strlen(c)*sizeof(char)) + 1;
        if(c == NULL || len == 1)
            break;
        line = kmalloc(len, GFP_KERNEL);
        memset(line, 0, len);
        if(line == NULL){

            printk("sbrack: cannot allocate memory\n");
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
            label = kmalloc(len, GFP_KERNEL);
            if(label == NULL){

                printk("sbrack: cannot allocate memory\n");
                err = -ENOMEM;
                goto out;
            }

            strncpy(label, c, len);
            if(oper == 1){
                kstrtoint(label, 10, &uid_ino);
                kfree(label);
            }
            else if(oper == 2){
                role = label;
            }
        }
        kfree(temp_line);
        oper = 0;
        if(user_file == 0){
        
            user_list = add_node_user_file_role(user_list, uid_ino, role);
        }
        else{
            file_list = add_node_user_file_role(file_list, uid_ino, role);
        }
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
        line = kmalloc(len, GFP_KERNEL);
        memset(line, 0, len);
        if(line == NULL){

            printk("sbrack: cannot allocate memory\n");
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
            label = kmalloc(len, GFP_KERNEL);
            if(label == NULL){

                printk("sbrack: cannot allocate memory\n");
                err = -ENOMEM;
                goto out;
            }

            strncpy(label, c, len);
            if(oper == 1){
                kstrtoint(label, 10, &role_id);
                kfree(label);
            }
            else if(oper == 2){
                role = label;
            }
            else if(oper == 3){
                access = label;
            }
        }
        kfree(temp_line);
        oper = 0;
        role_list = add_node_role(role_list, role_id, role, access);
    }

out:
    return err;
}

/* function to clear lists */
void exit_user_file_role_rules(void){
    user_list_file_role_exit(user_list);
    user_list_file_role_exit(file_list);
    role_list_exit(role_list);
}

/* function to populate lists */
int read_user_file_role_rules(void){
    char *buf = NULL, *temp_buf = NULL;
    int byte = 0;

    user_list = user_file_list_init(user_list);
    if(IS_ERR(user_list))
        goto out;

    file_list = user_file_list_init(file_list);
    if(IS_ERR(file_list))
        goto out;
        
    role_list = role_list_init();
    if(IS_ERR(role_list))
        goto out;
    
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    memset(buf, 0, PAGE_SIZE*sizeof(char));
    byte = read_file("/etc/user_role", buf, PAGE_SIZE);
    
    temp_buf = buf;
    
    if(byte == -ENODATA){
        printk("sbrack: User configuration file is empty\n");
    }
    else if(byte < 0){
        printk("sbrack: User configuration file cannot be open. err: %d\n", byte);    
        goto free_buf;
    }
    else
        parse_user_file_role_buf(buf, 0);

    buf = temp_buf;
    
    memset(buf, 0, PAGE_SIZE*sizeof(char));
    byte = read_file("/etc/file_role", buf, PAGE_SIZE);
    
    if(byte == -ENODATA){
        printk("sbrack: File configuration file is empty\n");
    }
    else if(byte < 0){
        printk("sbrack: File configuration file cannot be open. err: %d\n", byte);    
        goto free_user;
    }
    else
        parse_user_file_role_buf(buf, 1);
        
    buf = temp_buf;

    memset(buf, 0, PAGE_SIZE*sizeof(char));
    byte = read_file("/etc/role_rule", buf, PAGE_SIZE);
    
    if(byte == -ENODATA){
        printk("sbrack: Role configuration file is empty\n");
    }
    else if(byte < 0){
        printk("sbrack: Role configuration file cannot be open. err: %d\n", byte);    
        goto free_file;
    }
    else
        parse_role_buf(buf);

    goto free_buf;
    
free_file:
    user_list_file_role_exit(file_list);
free_user:
    user_list_file_role_exit(user_list);
free_buf:    
    kfree(temp_buf);
out:
    if(byte < 0)
        return byte;
    else
        return 0;
}

/* function to check access based on roles*/
int __check_access(struct node_role *list, char *role1, char *role2){
    
    struct node_role *temp = NULL;
    int access = 0;
    char *is_present = NULL;
    
    if(list == NULL){
        printk("sbrack: Role list is not initialized. Cannot check access.\n");
        return -EINVAL;
    }

    temp = list->next;
    while(temp){
        if(strcmp(temp->role, role1) == 0){
            is_present = strstr(temp->access, role2);
            
            if(is_present)
                access = 1;
            
            break;
        }
            
        if(temp)
            temp = temp->next;
    }
    
    return access;
}

/* function to check access based on uid and ino */
int check_access(int uid, int ino){
    int ret = 0;
    struct node_user_file_role *user_temp = NULL, *file_temp = NULL;
    
    exit_user_file_role_rules();
    read_user_file_role_rules();
    
    user_temp = find_user_file_role_node(user_list, uid);
    if(user_temp == NULL){
        printk("sbrack: User doesn't exist in configuration file\n");
        ret = -ENOENT;
        goto out;
    }
    
    file_temp = find_user_file_role_node(file_list, ino);
    if(file_temp == NULL){
        printk("sbrack: File doesn't exist in configuration file\n");
        ret = -ENOENT;
        goto out;
    }

    ret = __check_access(role_list, user_temp->role, file_temp->role);
   
out:    
    return ret;
}

/* function to check permission based on uid and ino */
int check_permission(int uid, int ino){
    int ret = 0;
    struct node_user_file_role *user_temp = NULL, *file_temp = NULL;
    
    if(user_list && file_list && role_list){
        user_temp = find_user_file_role_node(user_list, uid);
        if(user_temp == NULL){
            printk("sbrack: User doesn't exist in configuration file\n");
            ret = -ENOENT;
            goto out;
        }
        
        file_temp = find_user_file_role_node(file_list, ino);
        if(file_temp == NULL){
            printk("sbrack: File doesn't exist in configuration file\n");
            ret = -ENOENT;
            goto out;
        }

        ret = __check_access(role_list, user_temp->role, file_temp->role);
    }
    else
        ret = -ENOENT;
out:    
    return ret;
}

/* function to add file's role */
int add_file_role(int ino, int uid){
    int ret = 0;
    char *temp_role = NULL;
    struct node_user_file_role *temp = NULL;
    
    exit_user_file_role_rules();  
    ret = read_user_file_role_rules();
    
    if(ret != 0)
        goto out;
    
    temp = find_user_file_role_node(file_list, ino);
    
    if(temp != NULL){
        printk("sbrack: File mapping already exists\n");
        ret = -EEXIST;
        goto out;
    }
    
    temp = find_user_file_role_node(user_list, uid);
    
    if(temp == NULL){
        printk("sbrack: Cannot add this file's mapping. User doesn't exists\n");
        ret = -EPERM;
        goto out;
    }
    
    temp_role = kmalloc(strlen(temp->role), GFP_KERNEL);
    strcpy(temp_role, temp->role);

    file_list = add_node_user_file_role(file_list, ino, temp_role);
    
    if(IS_ERR(file_list)){
        ret = PTR_ERR(file_list);
        goto out;
    }
    
    ret = write_file(file_list);

out:    
    return ret;
}

/* function to delete file's role */
int delete_file_role(int ino){
    int ret = 0;
    struct node_user_file_role *temp = NULL;
    
    exit_user_file_role_rules();    
    ret = read_user_file_role_rules();
    
    if(ret != 0)
        goto out;
    
    temp = find_user_file_role_node(file_list, ino);
    
    if(temp == NULL){
        printk("sbrack: File mapping doesn't exists\n");
        ret = -ENODATA;
        goto out;
    }
    
    file_list = delete_node_user_file_role(file_list, ino);
    
    if(IS_ERR(file_list)){
        ret = PTR_ERR(file_list);
        goto out;
    }
    
    ret = write_file(file_list);

out:    
    return ret;
}