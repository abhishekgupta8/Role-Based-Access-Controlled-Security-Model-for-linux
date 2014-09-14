#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/security.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "sbrack.h"

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#ifdef CONFIG_SECURITY_SBRACK 

/* this hook labels the new inodes */
static int sbrack_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                   const char **name, void **value, size_t *len)
{
    if(get_current_user()->uid.val >= 1000){        
    
        add_file_role(inode->i_ino, get_current_user()->uid.val);
    }
    
    return 0;
}

/* check for new file */
static int sbrack_inode_create(struct inode *inode, struct dentry *dentry,
                umode_t mask)
{
    
    int ret = 0;

    if(get_current_user()->uid.val >= 1000){
        
        ret = check_access(get_current_user()->uid.val, inode->i_ino);
        
        if(ret == 1)
            return 0;
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }

    return 0;
}

/* check for new link */
static int sbrack_inode_link(struct dentry *old_dentry, struct inode *inode,
              struct dentry *new_dentry)
{   
    int ret = 0;

    if(get_current_user()->uid.val >= 1000){
        
        ret = check_access(get_current_user()->uid.val, old_dentry->d_inode->i_ino);
        
        if(ret == 1)
            return 0;
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }
    
    return 0;
}

/* check for unlinking in parent directory 
   This function removes the file mapping from the sbrack config files as well */ 
static int sbrack_inode_unlink(struct inode *inode, struct dentry *dentry)
{    
    int ret = 0;
        
    if(get_current_user()->uid.val >= 1000){        
        
        ret = check_access(get_current_user()->uid.val, dentry->d_inode->i_ino);

        if(ret == 1)
            delete_file_role(dentry->d_inode->i_ino);
        else if(ret == 0)
            return -EACCES;
    }
    return 0;
}

/* check permission for creating symlink */
static int sbrack_inode_symlink(struct inode *inode, struct dentry *dentry,
                 const char *name)
{  
    int ret = 0;

    if(get_current_user()->uid.val >= 1000){
        
        ret = check_access(get_current_user()->uid.val, inode->i_ino);
        
        if(ret == 1)
            return 0;
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }
    
    return 0;
}

/* check permission for creating mv/cp */
static int sbrack_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                struct inode *new_inode, struct dentry *new_dentry)
{   
    int ret = 0;

    if(get_current_user()->uid.val >= 1000){
    
        /* checking if permission is to mv/cp the file/directory */    
        ret = check_access(get_current_user()->uid.val, old_dentry->d_inode->i_ino);
        
        if(ret == 1){
        
            /* checking if permission is to mv/cp the file/directory to the new parent directory*/
            ret = check_access(get_current_user()->uid.val, new_inode->i_ino);
            
            if(ret == 1)
                return 0;
            else if(ret == 0)
                return -EACCES;
            else 
                return 0;
        }
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }

    return 0;
}

/* check permission for accessing symlink */
static int sbrack_inode_readlink(struct dentry *dentry)
{   
    int ret = 0;

    if(get_current_user()->uid.val >= 1000){
        
        ret = check_access(get_current_user()->uid.val, dentry->d_inode->i_ino);
        
        if(ret == 1)
            return 0;
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }
    
    return 0;
}

/* check permission for accessing already created files */
static int sbrack_inode_permission(struct inode *inode, int mask)
{    
    int ret = 0;
    
    if(get_current_user()->uid.val >= 1000 && !S_ISDIR(inode->i_mode)){
        
        ret = check_permission(get_current_user()->uid.val, inode->i_ino);
        
        if(ret == 1)
            return 0;
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }
    
    return 0;
}

/* check permission for creating directory in the parent directory */
static int sbrack_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int ret = 0;
    
    if(get_current_user()->uid.val >= 1000){
        
        ret = check_access(get_current_user()->uid.val, dir->i_ino);
        
        if(ret == 1)
            return 0;
        else if(ret == 0)
            return -EACCES;
        else 
            return 0;
    }

    return 0;
}

/* check permission for removing directory. 
   This function removes the directory mapping from the sbrack config files as well*/
static int sbrack_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
    
    int ret = 0;
    
    if(get_current_user()->uid.val >= 1000){        
        
        ret = check_access(get_current_user()->uid.val, dentry->d_inode->i_ino);

        if(ret == 1)
            delete_file_role(dentry->d_inode->i_ino);
        else if(ret == 0)
            return -EACCES;
    }

    return 0;
}

/* overwriting function pointers to exploit hooks */
static struct security_operations sbrack_ops = {
    .name =                          "SBRACK",
    .inode_init_security =        sbrack_inode_init_security,
    .inode_create =                  sbrack_inode_create,
    .inode_link =                 sbrack_inode_link,
    .inode_unlink =               sbrack_inode_unlink,
    .inode_symlink =              sbrack_inode_symlink,
    .inode_mkdir =                sbrack_inode_mkdir,
    .inode_rmdir =                sbrack_inode_rmdir,
    .inode_rename =               sbrack_inode_rename,
    .inode_readlink =             sbrack_inode_readlink,
    .inode_permission =           sbrack_inode_permission
};

static int __init sbrack_init(void){

    /* registering the hooks */        
    if (register_security(&sbrack_ops))
        printk("sbrack: Unable to register sbrack with kernel.\n");
    else 
        printk("sbrack: Registered with the kernel\n");

    return 0;
}

static void __exit sbrack_exit (void)
{   
    /* memory clean up */
    exit_user_file_role_rules();
}

module_init (sbrack_init);
module_exit (sbrack_exit);

MODULE_DESCRIPTION("sbrack");
MODULE_LICENSE("GPL");
#endif /* CONFIG_SECURITY_SBRACK */