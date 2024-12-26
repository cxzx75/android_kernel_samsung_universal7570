#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <asm/setup.h>

/*
 * Maximum length for the SELinux boot parameter
 * Prevents potential buffer overflows
 */
#define SELINUX_PARAM_LENGTH 32

#ifdef CONFIG_SECURITY_SELINUX_PERMISSIVE
static char *proc_cmdline;
#endif

/*
 * Display the kernel command line parameters
 * Uses seq_file interface for proper handling of large outputs
 */
static int cmdline_proc_show(struct seq_file *m, void *v)
{
    if (!m)
        return -EINVAL;

#ifdef CONFIG_SECURITY_SELINUX_PERMISSIVE
    if (proc_cmdline)
        seq_printf(m, "%s\n", proc_cmdline);
#else
    if (saved_command_line)
        seq_printf(m, "%s\n", saved_command_line);
#endif
    return 0;
}

/*
 * Open handler for /proc/cmdline
 * Initializes the seq_file for reading
 */
static int cmdline_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = cmdline_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

/*
 * Parse SELinux boot parameter and modify if needed
 * Returns modified command line or NULL on error
 */
#ifdef CONFIG_SECURITY_SELINUX_PERMISSIVE
static char *parse_selinux_cmdline(const char *cmdline)
{
    char *new_cmdline;
    const char *selinux_param = "androidboot.selinux=";
    char *param_start, *param_end;
    size_t prefix_len, suffix_len;

    if (!cmdline)
        return NULL;

    param_start = strstr(cmdline, selinux_param);
    if (!param_start) {
        /* No SELinux parameter found, copy as-is */
        new_cmdline = kstrdup(cmdline, GFP_KERNEL);
        return new_cmdline;
    }

    param_start = strchr(param_start, '=');
    if (!param_start)
        return NULL;

    param_end = strchr(param_start, ' ');
    if (!param_end)
        param_end = param_start + strlen(param_start);

    /* Calculate lengths for new string */
    prefix_len = param_start - cmdline + 1;
    suffix_len = strlen(param_end);

    /* Allocate new command line with enough space */
    new_cmdline = kmalloc(prefix_len + strlen("permissive") + suffix_len + 1, 
                         GFP_KERNEL);
    if (!new_cmdline)
        return NULL;

    /* Construct new command line with "permissive" parameter */
    scnprintf(new_cmdline, COMMAND_LINE_SIZE, "%.*spermissive%s",
             (int)prefix_len, cmdline, param_end);

    return new_cmdline;
}
#endif

static int __init proc_cmdline_init(void)
{
#ifdef CONFIG_SECURITY_SELINUX_PERMISSIVE
    proc_cmdline = parse_selinux_cmdline(saved_command_line);
    if (!proc_cmdline)
        return -ENOMEM;
#endif

    if (!proc_create("cmdline", 0444, NULL, &cmdline_proc_fops))
        goto fail;

    return 0;

fail:
#ifdef CONFIG_SECURITY_SELINUX_PERMISSIVE
    kfree(proc_cmdline);
#endif
    return -ENOMEM;
}

#ifdef CONFIG_SECURITY_SELINUX_PERMISSIVE
static void __exit proc_cmdline_exit(void)
{
    remove_proc_entry("cmdline", NULL);
    kfree(proc_cmdline);
}
module_exit(proc_cmdline_exit);
#endif

fs_initcall(proc_cmdline_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel Command Line Handler");
MODULE_AUTHOR("cxzx");
